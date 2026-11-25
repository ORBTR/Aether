//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/health"
	"github.com/quic-go/quic-go"
)

// QUICSession implements Session over a QUIC connection.
// QUIC provides native streams, reliability, flow control, congestion control,
// and encryption. The adapter is the SIMPLEST — it maps Aether stream operations
// directly to QUIC bidirectional stream operations with zero protocol overhead.
//
// Aether provides: stream lifecycle (OPEN/CLOSE/RESET semantics only).
// QUIC provides: EVERYTHING ELSE (reliability, flow control, congestion, mux, encryption).
type QUICSession struct {
	// BaseSession owns the identity + lifecycle + accessor surface
	// (LocalNodeID/RemoteNodeID/LocalPeerID/RemotePeerID/ConnectionID/
	// Capabilities/Protocol/Health/IsClosed/LastActivity/IdleTimeout)
	// shared with the Noise + TCP adapters. Embedded as a pointer so
	// the close-signal channel + sync.Once are safe across all three
	// goroutines (read loop, accept loop, caller-driven Close).
	*aether.BaseSession

	conn    quic.Connection
	streams map[uint64]*quicStream
	// acceptor owns per-StreamID accept dispatch — pinned waiters,
	// per-ID backlog, and the FIFO that AcceptStream drains. Shared
	// transport-agnostic implementation in the root aether package, so
	// the Noise, TCP, and QUIC adapters do not each carry their own
	// channel + push-mode shim. acceptLoop calls acceptor.Notify;
	// AcceptStream and AcceptStreamByID delegate to it.
	acceptor *aether.StreamAcceptor
	mu       sync.Mutex

	// wireExchange is the preface exchange (exchangeWireVersions): OpenStream waits
	// on it, and acceptLoop reads no stream header before it, since a peer of another
	// frame grammar lays the OPEN payload in a header out differently. wireOffer is
	// what this side offers, and wireOfferErr that offer's refusal. Both are set in
	// NewQuicSession before any goroutine starts and never change.
	wireExchange
	wireOffer      aether.WireVersions
	wireOfferErr   error
	prefaceTimeout time.Duration

	// probeOut is this side's probe stream (writeProbe), opened at the first PING or
	// PONG it writes. probeMu holds one frame's write whole, since Ping's goroutine
	// and serveProbes' answer share the stream.
	probeMu  sync.Mutex
	probeOut quic.SendStream
}

// quicWireRefusalCode is the QUIC application error a session closes with when its
// preface exchange refuses the peer. Closing the connection can overtake this side's
// preface, so a peer whose own exchange then fails reads this code as the refusal
// (exchangeWireVersions).
const quicWireRefusalCode quic.ApplicationErrorCode = 0x57

// quicStream wraps a native QUIC bidirectional stream as an Aether Stream.
type quicStream struct {
	streamID   uint64
	quicStream quic.Stream
	config     aether.StreamConfig
	state      *aether.StreamStateMachine
	session    *QUICSession
	connOnce   sync.Once
	connView   net.Conn
	sends      sendGate      // one Send writes at a time; see Send
	rx         quicFrameRead // the frame Receive is partway through; see Receive
}

// NewQuicSession creates an Aether session over a QUIC connection and starts the
// wire version exchange. app is what an application adds to aether's own entries in
// the set it offers (aether.LocalWireVersions).
func NewQuicSession(conn quic.Connection, localNodeID, remoteNodeID aether.NodeID, app ...aether.WireVersion) *QUICSession {
	base := aether.NewBaseSession(localNodeID, remoteNodeID, aether.ProtoQUIC)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	s := &QUICSession{
		BaseSession: base,
		conn:        conn,
		streams:     make(map[uint64]*quicStream),

		wireExchange:   newWireExchange(),
		prefaceTimeout: wireVersionsPrefaceTimeout,
	}
	s.wireOffer, s.wireOfferErr = aether.LocalWireVersions(app)
	// Per-StreamID accept dispatch + AcceptStream FIFO — shared
	// implementation in the root aether package. BlockUntilClose: when the
	// FIFO fills up the accept loop (acceptLoop) blocks until a consumer
	// drains or the session closes, rather than dropping streams. QUIC has
	// no other backpressure surface to push on, so blocking is the right
	// signal.
	s.acceptor = aether.NewStreamAcceptor(aether.StreamAcceptorConfig{
		Mode:      aether.BlockUntilClose,
		Closed:    base.CloseSignal(),
		ErrClosed: aether.ErrSessionClosed,
	})
	s.wireTimer.Store(time.AfterFunc(s.prefaceTimeout, func() {
		if s.finishWireVersions(aether.NegotiatedWireVersions{}, errWireVersionsPrefaceTimeout) {
			s.closeRefused(errWireVersionsPrefaceTimeout)
		}
	}))
	go s.exchangeWireVersions()
	go s.acceptLoop()
	return s
}

// exchangeWireVersions runs the preface exchange: each side opens one unidirectional
// QUIC stream, writes its preface on it and closes it, and reads the peer's from the
// one it accepts. Aether's streams are bidirectional, so the unidirectional stream
// cannot be mistaken for one, and neither side waits for the other to write first.
// The peer's read needs the write to have finished, so a refusal waits for it before
// the close, as far as the connection lets it: a peer whose read loses to that close
// reads quicWireRefusalCode as the same refusal.
func (s *QUICSession) exchangeWireVersions() {
	if s.wireOfferErr != nil {
		s.refuseWire(s.wireOfferErr)
		return
	}
	written := make(chan error, 1)
	go func() { written <- s.writePreface() }()
	chosen, err := s.readPreface()
	if err != nil {
		select {
		case werr := <-written:
			// The read's failure is the refusal; the write is awaited only so the
			// peer can read this side's preface before the close, and its own
			// failure changes nothing the refusal says.
			_ = werr
		case <-s.CloseSignal():
		case <-time.After(s.prefaceTimeout):
		}
		s.refuseWire(err)
		return
	}
	// writeProbe opens a unidirectional stream once the exchange has ended, and the
	// peer's readPreface takes the first one this side opens, so the preface's stream
	// is opened before the exchange ends.
	select {
	case werr := <-written:
		// A preface this side could not write is one the peer cannot read: the
		// exchange refuses, as a failed read does above.
		if werr != nil {
			s.refuseWire(fmt.Errorf("wire versions preface: %w", werr))
			return
		}
	case <-s.CloseSignal():
		return
	}
	if s.finishWireVersions(chosen, nil) {
		s.serveProbes()
	}
}

func (s *QUICSession) writePreface() error {
	st, err := s.conn.OpenUniStreamSync(s.conn.Context())
	if err != nil {
		return err
	}
	if err := aether.WriteWireVersionsPreface(st, s.wireOffer); err != nil {
		return err
	}
	return st.Close()
}

// readPreface reads the peer's preface and makes the choice from the two offers. A
// connection the peer closed with quicWireRefusalCode is the peer's refusal, which
// names the same mismatch this side would have found.
func (s *QUICSession) readPreface() (aether.NegotiatedWireVersions, error) {
	rs, err := s.conn.AcceptUniStream(s.conn.Context())
	var peer aether.WireVersions
	if err == nil {
		peer, err = aether.ReadWireVersionsPreface(rs)
	}
	if err != nil {
		var refused *quic.ApplicationError
		if errors.As(err, &refused) && refused.Remote && refused.ErrorCode == quicWireRefusalCode {
			return aether.NegotiatedWireVersions{}, fmt.Errorf("%w: refused by the peer: %s", aether.ErrWireVersionMismatch, refused.ErrorMessage)
		}
		return aether.NegotiatedWireVersions{}, fmt.Errorf("wire versions preface: %w", err)
	}
	return aether.ChooseWireVersions(s.wireOffer, peer)
}

// refuseWire ends the exchange with err and closes the session, if nothing has ended
// the exchange first.
func (s *QUICSession) refuseWire(err error) {
	if s.finishWireVersions(aether.NegotiatedWireVersions{}, err) {
		s.closeRefused(err)
	}
}

// closeRefused closes a session whose preface exchange refused its peer, recording
// err as the close reason and sending it as the connection's error.
func (s *QUICSession) closeRefused(err error) {
	if !s.SignalClose() {
		return
	}
	s.SetCloseErr(err)
	if s.acceptor != nil {
		_ = s.acceptor.Close()
	}
	_ = s.conn.CloseWithError(quicWireRefusalCode, err.Error())
}

// WireVersions returns the set the preface exchange chose (wireExchange.chosenWire).
func (s *QUICSession) WireVersions() aether.NegotiatedWireVersions {
	return s.chosenWire(s.CloseSignal())
}

// acceptLoop accepts incoming QUIC streams and wraps them as Aether streams, once
// the preface exchange has chosen a set: a session that refused its peer holds no
// stream state.
func (s *QUICSession) acceptLoop() {
	select {
	case <-s.wireDone:
	case <-s.CloseSignal():
		return
	}
	if r := s.wireResult.Load(); r.err != nil {
		return
	}
	for {
		qs, err := s.conn.AcceptStream(context.Background())
		if err != nil {
			return // connection closed
		}

		// Read stream header: [StreamID:8][OpenPayload:OpenPayloadSize].
		// The payload's InitialCredit is not read: QUIC owns the stream's
		// flow control. Its Generation is not read either: this stream is a QUIC
		// stream of its own, which QUIC hands out once, so no frame of another
		// stream reaches it. The preface exchange has fixed the grammar this layout is.
		var hdr [8 + aether.OpenPayloadSize]byte
		if _, err := io.ReadFull(qs, hdr[:]); err != nil {
			qs.CancelRead(0)
			continue
		}

		streamID := binary.BigEndian.Uint64(hdr[0:8])
		openPayload := aether.DecodeOpenPayload(hdr[8:])

		st := &quicStream{
			streamID:   streamID,
			quicStream: qs,
			config: aether.StreamConfig{
				StreamID:    streamID,
				Reliability: openPayload.Reliability,
				Priority:    openPayload.Priority,
				Dependency:  openPayload.Dependency,
			},
			state:   aether.NewStreamStateMachine(),
			session: s,
		}
		recordStreamEvent(st.state, aether.EventRecvOpen)

		// An aether StreamID must be unique per live session. A second
		// QUIC stream presenting an already-registered StreamID is a
		// protocol violation — refuse the DUPLICATE transport stream
		// rather than silently overwriting the map entry. Overwriting
		// corrupts Metrics().ActiveStreams and, via dropStream, lets
		// either stream's close evict the survivor's slot. The first
		// stream keeps its mapping; quic-go's MaxIncomingStreams still
		// bounds total concurrent streams, so no limit is lowered. Mirrors
		// tcp.go registerStream's duplicate handling.
		s.mu.Lock()
		if _, dup := s.streams[streamID]; dup {
			s.mu.Unlock()
			qs.CancelRead(quic.StreamErrorCode(aether.ResetRefused))
			qs.CancelWrite(quic.StreamErrorCode(aether.ResetRefused))
			continue
		}
		s.streams[streamID] = st
		s.mu.Unlock()

		// Hand to the shared per-StreamID dispatcher. Notify always
		// makes progress (waiter / backlog / fallback). If the
		// session has closed mid-dispatch the acceptor's isClosed
		// guard rejects the notify and the loop continues; we exit
		// on the next conn.AcceptStream error instead.
		s.acceptor.Notify(st)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface
// ────────────────────────────────────────────────────────────────────────────

// OpenStream opens a stream under cfg.StreamID, or refuses with
// aether.ErrDuplicateStreamID, before anything reaches the wire, when a stream
// holds that ID: the peer's acceptLoop would refuse the second one, and the stream
// in place keeps its map entry.
func (s *QUICSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		if err := s.wireRefusal(); err != nil {
			return nil, err
		}
		return nil, aether.ErrSessionClosed
	default:
	}
	// No stream exists before the wire versions are chosen: a refused peer returns
	// the refusal here and the session holds nothing to tear down.
	if err := s.awaitWire(ctx, s.CloseSignal()); err != nil {
		return nil, err
	}

	st := &quicStream{
		streamID: cfg.StreamID,
		config:   cfg,
		state:    aether.NewStreamStateMachine(),
		session:  s,
	}
	// The map entry holds the ID across the two blocking calls below; only the
	// duplicate check and Metrics read an entry, so it needs no QUIC stream yet.
	s.mu.Lock()
	if _, dup := s.streams[cfg.StreamID]; dup {
		s.mu.Unlock()
		return nil, fmt.Errorf("OpenStream stream=%d: %w", cfg.StreamID, aether.ErrDuplicateStreamID)
	}
	s.streams[cfg.StreamID] = st
	s.mu.Unlock()

	qs, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		st.dropStream()
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	// Write stream header: [StreamID:8][OpenPayload:OpenPayloadSize]. The
	// payload states InitialCredit zero, no aether stream credit: QUIC owns
	// the stream's flow control, and acceptLoop does not read the field. It
	// states Generation zero too, which acceptLoop does not read: the QUIC
	// stream itself is the incarnation.
	var hdr [8 + aether.OpenPayloadSize]byte
	binary.BigEndian.PutUint64(hdr[0:8], cfg.StreamID)
	copy(hdr[8:], aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	}))
	if _, err := qs.Write(hdr[:]); err != nil {
		qs.CancelRead(0)
		qs.CancelWrite(0)
		st.dropStream()
		return nil, fmt.Errorf("write stream header: %w", err)
	}

	st.quicStream = qs
	recordStreamEvent(st.state, aether.EventSendOpen)
	return st, nil
}

// AcceptStream delegates to the shared aether.StreamAcceptor, which owns
// the FIFO channel and the per-StreamID dispatch for every adapter. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *QUICSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	st, err := s.acceptor.Accept(ctx)
	if err != nil {
		if werr := s.wireRefusal(); werr != nil {
			return nil, werr
		}
	}
	return st, err
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so all three transport adapters share one
// implementation.
func (s *QUICSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	st, err := s.acceptor.AcceptByID(ctx, streamID)
	if err != nil {
		if werr := s.wireRefusal(); werr != nil {
			return nil, werr
		}
	}
	return st, err
}

// Ping writes a PING on this side's probe stream and waits for the peer's PONG, as the
// Noise and TCP adapters do on their keepalive stream: aether.WaitForActivityPing holds
// the wait, and the PONG feeds the session's RTT estimator, which aether.KeepalivePlanFor
// reads. quic-go's own keepalive frames answer nothing a caller can read, so this
// exchange is the session's only round-trip measurement. A connection QUIC has already
// torn down (transport close, idle timeout, a peer's CONNECTION_CLOSE) answers
// ErrSessionClosed, which multipath's probeNonPrimary and aether.RunKeepalive read as a
// failed probe.
func (s *QUICSession) Ping(ctx context.Context) (time.Duration, error) {
	if err := s.awaitWire(ctx, s.CloseSignal()); err != nil {
		return 0, err
	}
	if err := s.conn.Context().Err(); err != nil {
		return 0, aether.ErrSessionClosed
	}
	return aether.WaitForActivityPing(ctx, s.Health(), s.CloseSignal(), func(seqNo uint32) error {
		return s.writeProbe(ctx, &aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   aether.DefaultStreamLayout().Keepalive,
			Type:       aether.TypePING,
			SeqNo:      seqNo,
		})
	})
}

// writeProbe writes f on this side's probe stream: one unidirectional QUIC stream
// carrying this side's PING and PONG frames, opened at the first of them. A
// unidirectional stream takes no aether stream ID, so it cannot meet a stream the
// application opened under the keepalive ID; acceptLoop only accepts bidirectional
// streams. ctx's deadline, or PingDefaultDeadline without one, bounds a write the
// peer's flow control holds, so a peer that stops reading cannot hold probeMu past it.
func (s *QUICSession) writeProbe(ctx context.Context, f *aether.Frame) error {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.probeOut == nil {
		st, err := s.conn.OpenUniStreamSync(ctx)
		if err != nil {
			return fmt.Errorf("quic probe stream: %w", err)
		}
		s.probeOut = st
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(aether.PingDefaultDeadline)
	}
	if err := s.probeOut.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := aether.EncodeFrame(s.probeOut, f)
	return err
}

// serveProbes reads the peer's probe stream until the connection ends: the one
// unidirectional stream the peer opens after its preface. It answers each PING and
// records each PONG through the same aether.ControlFrameHandler the Noise and TCP
// adapters dispatch to, and refuses the stream at any other frame, since no other
// frame travels on it. exchangeWireVersions runs it once the exchange has chosen a set.
func (s *QUICSession) serveProbes() {
	rs, err := s.conn.AcceptUniStream(s.conn.Context())
	if err != nil {
		return
	}
	control := &aether.ControlFrameHandler{
		HealthMon: s.Health(),
		Writer: func(f *aether.Frame) error {
			ctx, cancel := context.WithTimeout(s.conn.Context(), aether.KeepalivePlanFor(s).ProbeTimeout)
			defer cancel()
			return s.writeProbe(ctx, f)
		},
		Sender:            s.LocalPeerID(),
		Receiver:          s.RemotePeerID(),
		KeepaliveStreamID: aether.DefaultStreamLayout().Keepalive,
	}
	for {
		frame, err := aether.DecodeFrame(rs)
		if err != nil {
			return
		}
		s.Health().RecordActivity()
		switch frame.Type {
		case aether.TypePING:
			control.HandlePing(frame)
		case aether.TypePONG:
			control.HandlePong(frame)
		default:
			rs.CancelRead(quic.StreamErrorCode(aether.ResetRefused))
			return
		}
	}
}

func (s *QUICSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	// QUIC uses connection close with error code
	return s.conn.CloseWithError(quic.ApplicationErrorCode(reason), message)
}

func (s *QUICSession) Close() error {
	if !s.SignalClose() {
		return nil
	}
	// A close before the preface exchange ended ends it, releasing every waiter
	// and stopping the deadline timer.
	s.finishWireVersions(aether.NegotiatedWireVersions{}, aether.ErrSessionClosed)
	// Release ByID waiters and drain the backlog; blocked
	// AcceptStreamByID callers return ErrSessionClosed. Drained
	// backlog streams are not Reset here because QUIC stream
	// cancel is handled by quic-go on conn close — calling
	// CancelRead/Write twice is harmless but redundant.
	if s.acceptor != nil {
		_ = s.acceptor.Close()
	}
	return s.conn.CloseWithError(0, "session closed")
}

func (s *QUICSession) SessionKey() []byte      { return nil } // QUIC handles encryption
func (s *QUICSession) CongestionWindow() int64 { return 0 }   // QUIC handles congestion
func (s *QUICSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	s.mu.Unlock()
	return aether.SessionMetrics{RTT: avg, ActiveStreams: streamCount, PingsReceived: s.Health().PingsReceived()}
}

// ────────────────────────────────────────────────────────────────────────────
// quicStream — aether.Stream interface
// ────────────────────────────────────────────────────────────────────────────

func (st *quicStream) StreamID() uint64            { return st.streamID }
func (st *quicStream) Config() aether.StreamConfig { return st.config }
func (st *quicStream) IsOpen() bool                { return st.state.IsOpen() }

func (st *quicStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.connView = NewStreamConn(st) })
	return st.connView
}

// Send writes data as one frame, a 4-byte length then the bytes, straight
// to the QUIC stream; QUIC carries reliability and flow control. ctx bounds
// the write: when ctx ends while the peer's flow control holds the frame,
// the stream's QUIC write deadline is moved to now, quic-go's Write
// returns, and Send returns ctx's error. That is how StreamConn's write
// deadline reaches a QUIC stream. A frame cut short partway would make the
// peer's Receive read the next frame's bytes as the rest of this one, so
// the stream's send side is cancelled instead (CancelWrite): the peer's
// Receive fails with the reset and every later Send fails. A frame of
// which nothing was written leaves the stream usable.
func (st *quicStream) Send(ctx context.Context, data []byte) error {
	if !st.state.CanSend() {
		return fmt.Errorf("stream %d: cannot send", st.streamID)
	}
	if err := st.sends.acquire(ctx); err != nil {
		return err
	}
	defer st.sends.release()
	if err := ctx.Err(); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	ended := st.boundWrite(ctx)
	n, err := st.quicStream.Write(lenBuf[:])
	if err == nil {
		var m int
		m, err = st.quicStream.Write(data)
		n += m
	}
	var timeout net.Error
	if ended() && errors.As(err, &timeout) && timeout.Timeout() {
		if n > 0 {
			st.quicStream.CancelWrite(quic.StreamErrorCode(aether.ResetCancel))
		}
		return ctx.Err()
	}
	return err
}

// boundWrite moves the stream's QUIC write deadline to now when ctx ends,
// which makes a blocked quic-go Write return. The returned func undoes it
// once the write is over and reports whether ctx ended it. Send holds the
// gate across both calls.
func (st *quicStream) boundWrite(ctx context.Context) (ended func() bool) {
	return moveDeadlineOnEnd(ctx, st.quicStream.SetWriteDeadline)
}

// boundRead moves the stream's QUIC read deadline to now when ctx ends,
// which makes a blocked quic-go Read return. The returned func undoes it
// once the read is over and reports whether ctx ended it. Receive calls
// both from the one goroutine that reads the stream.
func (st *quicStream) boundRead(ctx context.Context) (ended func() bool) {
	return moveDeadlineOnEnd(ctx, st.quicStream.SetReadDeadline)
}

// moveDeadlineOnEnd calls set(time.Now()) when ctx ends; set is one
// direction's deadline setter on a quic.Stream. The returned func stops
// that or, if the move has started, waits for it and then clears the
// deadline with set(time.Time{}), and reports whether the move ran. The
// clear follows the move, so the next call in that direction never meets a
// deadline left in the past. A ctx that cannot end sets nothing.
func moveDeadlineOnEnd(ctx context.Context, set func(time.Time) error) (ended func() bool) {
	if ctx.Done() == nil {
		return func() bool { return false }
	}
	moved := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = set(time.Now())
		close(moved)
	})
	return func() bool {
		if stop() {
			return false
		}
		<-moved
		_ = set(time.Time{})
		return true
	}
}

// Receive reads the next frame, a 4-byte length then that many bytes, from
// the QUIC stream. ctx bounds the read: when ctx ends while the read waits
// for the peer's bytes, the stream's QUIC read deadline is moved to now,
// quic-go's Read returns, and Receive returns ctx's error. That is how
// StreamConn's read deadline reaches a QUIC stream. The part of the frame
// read so far stays in rx and the next Receive goes on from it, so a
// Receive that ctx ended partway through a frame loses none of it and the
// stream stays usable. Any other failure ends the stream. A Receive whose
// ctx has already ended reads nothing. One goroutine calls Receive at a
// time, as StreamConn.Read does: rx and the QUIC read deadline belong to
// the stream, not to the call.
func (st *quicStream) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ended := st.boundRead(ctx)
	data, err := st.rx.read(st.quicStream)
	var timeout net.Error
	if ended() && errors.As(err, &timeout) && timeout.Timeout() {
		return nil, ctx.Err()
	}
	if err != nil {
		st.dropStream() // the stream has ended or its framing is lost
		return nil, err
	}
	st.session.Health().RecordActivity()
	return data, nil
}

// quicFrameRead is how far quicStream.Receive has read the frame at the
// head of its stream. n counts the bytes read of the 4-byte length and,
// once inBody is set, of the payload instead.
type quicFrameRead struct {
	length [4]byte
	body   []byte
	inBody bool
	n      int
}

// read reads r until the frame is whole and returns its payload. When r
// fails first, what was read stays, and the next read goes on from it.
func (f *quicFrameRead) read(r io.Reader) ([]byte, error) {
	if !f.inBody {
		if err := f.fill(r, f.length[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(f.length[:])
		if length > aether.MaxPayloadSize {
			return nil, fmt.Errorf("message too large: %d", length)
		}
		f.body, f.inBody, f.n = make([]byte, length), true, 0
	}
	if err := f.fill(r, f.body); err != nil {
		return nil, err
	}
	body := f.body
	*f = quicFrameRead{}
	return body, nil
}

// fill reads r into buf from f.n on until buf is full. Its errors are
// io.ReadFull's: io.EOF when r ends before any byte of buf, and
// io.ErrUnexpectedEOF when it ends partway.
func (f *quicFrameRead) fill(r io.Reader, buf []byte) error {
	for f.n < len(buf) {
		m, err := r.Read(buf[f.n:])
		f.n += m
		if err != nil && f.n < len(buf) {
			if err == io.EOF && f.n > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// dropStream evicts st from the session's stream map. Idempotent — only an
// entry that is st itself goes, so every quicStream termination path (Close,
// Reset, Receive EOF/error) can call it safely, however late, without touching a
// later stream that holds the ID. The QUIC
// streams map is otherwise write-only (its sole reader is Metrics for
// the ActiveStreams count), so without this eviction it grows by one
// pinned *quicStream — and the quic.Stream handle each retains — for
// every stream ever created on a long-lived connection: an unbounded
// leak. Mirrors the tcp/noise adapters' teardown discipline.
func (st *quicStream) dropStream() {
	st.session.mu.Lock()
	if cur, ok := st.session.streams[st.streamID]; ok && cur == st {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
}

func (st *quicStream) Close() error {
	recordStreamEvent(st.state, aether.EventSendFIN)
	err := st.quicStream.Close()
	st.dropStream()
	return err
}

func (st *quicStream) Reset(reason aether.ResetReason) error {
	recordStreamEvent(st.state, aether.EventSendReset)
	st.quicStream.CancelRead(quic.StreamErrorCode(reason))
	st.quicStream.CancelWrite(quic.StreamErrorCode(reason))
	st.dropStream()
	return nil
}

func (st *quicStream) SetPriority(weight uint8, dependency uint64) {
	// QUIC doesn't expose per-stream priority in quic-go
	// Priority is tracked in config for informational purposes
	st.config.Priority = weight
	st.config.Dependency = dependency
}

// Compile-time interface checks
var _ aether.Session = (*QUICSession)(nil)
var _ aether.Stream = (*quicStream)(nil)
