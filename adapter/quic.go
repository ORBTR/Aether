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
}

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

// NewQuicSession creates an Aether session over a QUIC connection.
func NewQuicSession(conn quic.Connection, localNodeID, remoteNodeID aether.NodeID) *QUICSession {
	base := aether.NewBaseSession(localNodeID, remoteNodeID, aether.ProtoQUIC)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	s := &QUICSession{
		BaseSession: base,
		conn:        conn,
		streams:     make(map[uint64]*quicStream),
	}
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
	go s.acceptLoop()
	return s
}

// acceptLoop accepts incoming QUIC streams and wraps them as Aether streams.
func (s *QUICSession) acceptLoop() {
	for {
		qs, err := s.conn.AcceptStream(context.Background())
		if err != nil {
			return // connection closed
		}

		// Read stream header: [StreamID:8][OpenPayload:10]
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
		st.state.Transition(aether.EventRecvOpen)

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

func (s *QUICSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		return nil, fmt.Errorf("session closed")
	default:
	}

	qs, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	// Write stream header: [StreamID:8][OpenPayload:10]
	var hdr [8 + aether.OpenPayloadSize]byte
	binary.BigEndian.PutUint64(hdr[0:8], cfg.StreamID)
	copy(hdr[8:], aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	}))
	if _, err := qs.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("write stream header: %w", err)
	}

	st := &quicStream{
		streamID:   cfg.StreamID,
		quicStream: qs,
		config:     cfg,
		state:      aether.NewStreamStateMachine(),
		session:    s,
	}
	st.state.Transition(aether.EventSendOpen)

	s.mu.Lock()
	if existing, dup := s.streams[cfg.StreamID]; dup {
		s.mu.Unlock()
		// Reject a duplicate local StreamID instead of overwriting, as
		// acceptLoop does: recycling an ID before the prior stream closed
		// would orphan the old quic.Stream (never CancelRead/Write'd) and let
		// a later dropStream on the stale entry evict the survivor. Cancel the
		// just-created QUIC stream we won't be tracking.
		_ = existing
		qs.CancelRead(0)
		qs.CancelWrite(0)
		return nil, fmt.Errorf("quic: stream %d already open", cfg.StreamID)
	}
	s.streams[cfg.StreamID] = st
	s.mu.Unlock()

	return st, nil
}

// AcceptStream delegates to the shared aether.StreamAcceptor, which owns
// the FIFO channel and the per-StreamID dispatch for every adapter. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *QUICSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	return s.acceptor.Accept(ctx)
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so all three transport adapters share one
// implementation.
func (s *QUICSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	return s.acceptor.AcceptByID(ctx, streamID)
}

// Ping reports session liveness for keepalive. QUIC has its own
// transport-layer keepalive so we don't write an aether-level PING
// frame, but we DO need to surface session death to callers: the cached
// RTT alone says nothing about a QUIC connection that has been torn down,
// and a keepalive that read only it would keep the session registered in
// the connection manager. So IsClosed is checked plus the underlying QUIC
// connection's context, which fires on transport close, idle timeout, or
// peer-initiated CONNECTION_CLOSE.
func (s *QUICSession) Ping(ctx context.Context) (time.Duration, error) {
	if s.IsClosed() {
		return 0, aether.ErrSessionClosed
	}
	if err := s.conn.Context().Err(); err != nil {
		return 0, aether.ErrSessionClosed
	}
	_, avg := s.Health().RTT()
	return avg, nil
}

func (s *QUICSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	// QUIC uses connection close with error code
	return s.conn.CloseWithError(quic.ApplicationErrorCode(reason), message)
}

func (s *QUICSession) Close() error {
	if !s.SignalClose() {
		return nil
	}
	// Release ByID waiters and drain the backlog; blocked
	// AcceptStreamByID callers return ErrSessionClosed. Drained
	// backlog streams are not Reset here because QUIC stream
	// cancel is handled by quic-go on conn close — calling
	// CancelRead/Write twice is harmless but redundant.
	if s.acceptor != nil {
		_ = s.acceptor.Close()
	}
	s.conn.CloseWithError(0, "session closed")
	return nil
}

func (s *QUICSession) SessionKey() []byte      { return nil } // QUIC handles encryption
func (s *QUICSession) CongestionWindow() int64 { return 0 }   // QUIC handles congestion
func (s *QUICSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	s.mu.Unlock()
	return aether.SessionMetrics{RTT: avg, ActiveStreams: streamCount}
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

// dropStream evicts st from the session's stream map. Idempotent — a
// delete of an absent key is a no-op, so every quicStream termination
// path (Close, Reset, Receive EOF/error) can call it safely. The QUIC
// streams map is otherwise write-only (its sole reader is Metrics for
// the ActiveStreams count), so without this eviction it grows by one
// pinned *quicStream — and the quic.Stream handle each retains — for
// every stream ever created on a long-lived connection: an unbounded
// leak. Mirrors the tcp/noise adapters' teardown discipline.
func (st *quicStream) dropStream() {
	st.session.mu.Lock()
	delete(st.session.streams, st.streamID)
	st.session.mu.Unlock()
}

func (st *quicStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	err := st.quicStream.Close()
	st.dropStream()
	return err
}

func (st *quicStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
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
