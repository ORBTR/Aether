//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// DefaultTCPMaxConcurrentStreams is the stream cap for TCP/WS/gRPC
// sessions (lower than Noise-UDP because one TCP conn is a narrower
// pipe and the head-of-line blocking risk from too many streams is higher).
// registerStream refuses opens past it with RESET(ResetRefused).
const DefaultTCPMaxConcurrentStreams = 256

// The per-StreamID backlog tuning constants (aether.MaxByIDBacklogPerStream,
// aether.ByIDBacklogGrace) live in the root package beside StreamAcceptor
// (stream_acceptor.go), which the Noise, TCP and QUIC adapters share, so one
// limit governs every adapter's accept backlog and none redeclares it here.

// TCPSession implements Session over a TCP/TLS connection.
// Provides Aether multiplexing (all streams share one conn), flow control,
// and the priority scheduler. Reliability comes from TCP natively.
type TCPSession struct {
	// BaseSession owns the identity + lifecycle + accessor surface
	// (LocalNodeID/RemoteNodeID/LocalPeerID/RemotePeerID/ConnectionID/
	// Capabilities/Protocol/Health/IsClosed/LastActivity/IdleTimeout)
	// shared with the Noise + QUIC adapters. Embedded as a pointer so
	// the close-signal channel + sync.Once are safe across the read /
	// write / housekeeping goroutines.
	*aether.BaseSession

	mu   sync.Mutex
	conn net.Conn

	layout        aether.StreamLayout
	opts          aether.SessionOptions
	classDefaults aether.TransportClassDefaults
	streams       map[uint64]*tcpStream

	// acceptor owns per-StreamID accept dispatch — pinned waiters,
	// per-ID backlog, and the FIFO that AcceptStream drains. Shared
	// transport-agnostic implementation in the root aether package, so
	// the Noise, TCP, and QUIC adapters do not each carry their own
	// channel + push-mode shim. handleOpen / handleImplicitOpen call
	// acceptor.Notify; AcceptStream and AcceptStreamByID delegate to
	// it.
	acceptor *aether.StreamAcceptor

	writeMu    sync.Mutex
	sched      *scheduler.Scheduler
	connWindow *flow.ConnWindow
	// txCompressor and rxCompressor are separate compressor states for TX
	// (encode: writeFrame, writeLoop's EncodeBatch) and RX (decode: readLoop's
	// ReadNextFrame), so cross-direction traffic never pollutes
	// SessionCompState identity (lastSender/lastReceiver) or a stream's
	// lastSeqNo/frameCount: one shared instance would flip the reconstructed
	// identity with the direction of the most recent full header and
	// cross-increment the frameCount%64 resync cadence, where dedicated state
	// per direction tracks identically on both peers. Both write and read
	// full frames only until readPreface applies the chosen set, so a frame
	// written before the peer's preface is read is a full frame.
	txCompressor *aether.Compressor
	rxCompressor *aether.Compressor

	// streamRefused counts peer-initiated OPEN requests rejected because
	// MaxConcurrentStreams was reached (registerStream).
	streamRefused uint64

	// Protocol-agnostic capabilities (cross-adapter parity with Noise —
	// these aren't Noise-specific concerns, they're session-level).
	streamGC     *aether.StreamGC     // idle stream auto-RESET
	abuseTracker *aether.AbuseTracker // per-peer misbehaviour scoring + threshold-breaker
	tickStop     chan struct{}        // shuts down the housekeeping ticker

	// throttle holds the explicit-CONGESTION signal state received from the
	// peer. Zero value is "no throttle"; handleCongestion updates it when a
	// CONGESTION frame arrives. Send-path consumers can consult Throttle()
	// for RateFactor/ShouldStall before committing to large sends.
	throttle aether.CongestionThrottle

	// Per-session delivery counters, session-aggregate across streams, the
	// same type NoiseSession.deliveryStats is. enqueueDelivery counts each
	// message it queues as delivered, a message that finds the queue already
	// holding unread messages as backpressure, and the message that finds it
	// full as dropped with its bytes (the one the stream's overrun reset
	// refuses). Surfaced through DeliveryStats() for the consumer that sums a
	// session's stats.
	deliveryStats DeliveryStats

	// wireOffer is the wire version offer this session's preface sends:
	// aether's entries plus opts.WireVersions (aether.LocalWireVersions).
	// wireOfferErr is that merge's refusal, which closes the session before
	// any preface is written. Both are set in NewTCPSession before any
	// goroutine starts and never change.
	wireOffer    aether.WireVersions
	wireOfferErr error

	// wireDone closes when the preface exchange ends: the peer's preface was
	// read and the choice made, or the exchange failed or the session closed
	// first. wireResult then holds the chosen set or the reason. OpenStream
	// waits on it and readLoop decodes no frame before it, which is what puts
	// the refusal of a mismatched peer ahead of every stream.
	// prefaceWritten closes once this side's preface write has returned, so
	// a refusing readLoop can let its preface reach the peer before the conn
	// closes and the peer reaches the same refusal. wireTimer ends an
	// exchange the peer leaves unanswered.
	wireDone       chan struct{}
	wireOnce       sync.Once
	wireResult     atomic.Pointer[tcpWireResult]
	prefaceWritten chan struct{}
	wireTimer      *time.Timer
	prefaceTimeout time.Duration

	// fragRecv is what a fragment this session receives must match. A
	// TCPSession's identity is established by its caller before construction
	// and binds it to no network key, so it has no realm: fragRecv refuses
	// every fragment (FragmentNoRealm), and Send never splits a message.
	// readPreface sets it from the chosen set before readLoop decodes a
	// frame; only readLoop reads it.
	fragRecv *FragmentReceiver
}

// tcpWireResult is the outcome of a TCPSession's preface exchange: the set
// both offers chose, or the reason there is none.
type tcpWireResult struct {
	chosen aether.NegotiatedWireVersions
	err    error
}

// wireVersionsPrefaceTimeout bounds a TCPSession's preface exchange: a peer
// whose preface has not arrived by then has the session closed with
// errWireVersionsPrefaceTimeout. NewTCPSession copies it into the session
// (prefaceTimeout), so a test can shorten it for the sessions it builds
// without racing sessions already running.
var wireVersionsPrefaceTimeout = 10 * time.Second

// errWireVersionsPrefaceTimeout is the close reason of a session whose peer
// sent no complete preface within wireVersionsPrefaceTimeout.
var errWireVersionsPrefaceTimeout = fmt.Errorf("%w: peer sent no preface within the deadline", aether.ErrHandshakeFailed)

// tcpStream is a single Aether stream multiplexed over a TCP connection.
type tcpStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *TCPSession
	state    *aether.StreamStateMachine
	// recvCh is the stream's delivery queue: the readLoop (deliverToStream,
	// through enqueueDelivery) puts each whole in-order message on it without
	// waiting, and Receive takes them. Its capacity,
	// tcpDeliveryQueueCapacity, is the most messages the consumer can leave
	// unread; a message that finds it full ends the stream through overrun,
	// because the readLoop also answers PING and serves the control plane and
	// every other stream, so it cannot wait on this consumer, and a byte-stream
	// session's sender holds no credit that would stop it first (Send ignores
	// its window). recvCh is never closed: its end is recvDone, which
	// closeRecvOnce closes exactly once (recvOnce) and Receive selects on,
	// draining what recvCh still holds before it returns the stream's end. A
	// close of recvCh would race the readLoop's send into it, since
	// closeRecvOnce also runs on application goroutines (Reset) and the
	// stream GC. recvDone is made in the struct literal with recvCh
	// (handleOpen, handleImplicitOpen, OpenStream); a stream built outside
	// those paths has no recvDone, and closeRecvOnce closes its recvCh
	// instead.
	recvCh   chan []byte
	recvDone chan struct{}
	// endErr is the reason the stream ended, when it is not an ordinary end:
	// aether.ErrStreamOverrun after either side's delivery queue overran
	// (overrun here, the peer's RESET(ResetFlowCtrl) in handleReset), or
	// aether.ErrStreamRefused after the peer's RESET(ResetRefused). Receive
	// returns it, once recvCh is drained, where it would return io.EOF, and
	// Send returns it for a stream that can no longer send. setEnd keeps the
	// first reason; nil means io.EOF.
	endErr atomic.Pointer[error]
	// fragBuf takes a peer's fragments (DATA frames flagged
	// aether.FlagFRAGMENT) and refuses each against the session's fragRecv,
	// which has no realm. Touched only by the readLoop (deliverToStream).
	fragBuf *FragmentBuffer
	window  *flow.StreamWindow
	// grantDebouncer coalesces stream-level WINDOW_UPDATE emissions driven
	// by application reads. Lazily attached by attachGrantDebouncer after
	// struct construction because the session method references must reach
	// the initialized receiver. TCP's reliable bytestream absorbs
	// transport-level pacing, but stream credit still gates the app-level
	// read flow so we debounce here too for parity with the noise adapter.
	grantDebouncer *grantDebouncer
	observe        *reliability.ObserveEngine // ACK-observe metrics (no enforcement)
	localSeq       uint32                     // monotonic counter (TCP doesn't set SeqNo)
	closed         bool
	mu             sync.Mutex
	connOnce       sync.Once
	connView       net.Conn // cached net.Conn wrapper
	recvOnce       sync.Once
	// recvEnded is set by closeRecvOnce before it closes recvDone (or
	// recvCh); enqueueDelivery reads it so nothing is queued after the
	// receive side's end.
	recvEnded atomic.Bool
}

// closeRecvOnce ends the stream's receive side exactly once: it sets
// recvEnded, so enqueueDelivery queues nothing more, and closes recvDone, on
// which Receive returns what recvCh still holds and then the stream's end
// (endError). Every termination path calls it (handleClose, handleReset,
// overrun, Reset, the OpenStream rollback, the stream GC through Reset), from
// the readLoop and from application goroutines, so recvOnce keeps the close
// idempotent. recvCh itself is never closed here because the readLoop may be
// sending into it on another goroutine; a stream built without recvDone
// (outside the open paths) has its recvCh closed instead, which Receive reads
// as the same end.
func (st *tcpStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		st.recvEnded.Store(true)
		if st.recvDone != nil {
			close(st.recvDone)
			return
		}
		close(st.recvCh)
	})
}

// setEnd records why the stream ended when that is not an ordinary end
// (endErr). The first reason is kept, so a RESET the peer sends after this
// side's overrun does not replace this side's own reason.
func (st *tcpStream) setEnd(err error) {
	st.endErr.CompareAndSwap(nil, &err)
}

// endError is what Receive returns once the receive side has ended and recvCh
// is drained, and what Send returns for a stream that can no longer send: the
// recorded reason (endErr) with the stream's ID, or ordinary when none was
// recorded.
func (st *tcpStream) endError(ordinary error) error {
	if p := st.endErr.Load(); p != nil {
		return fmt.Errorf("stream %d: %w", st.streamID, *p)
	}
	return ordinary
}

// attachGrantDebouncer initializes st.grantDebouncer bound to st.window
// and st.session.sendWindowUpdateAgnostic. Called after the stream is
// fully constructed + registered so the session back-reference is live.
// Safe to call once per stream; no-op if already attached.
func (st *tcpStream) attachGrantDebouncer() {
	if st.window == nil || st.session == nil {
		return
	}
	if st.grantDebouncer != nil {
		return
	}
	initialCredit := st.config.InitialCredit
	if initialCredit <= 0 {
		initialCredit = flow.DefaultStreamCredit
	}
	st.grantDebouncer = newGrantDebouncer(
		st.window,
		st.session.sendWindowUpdateAgnostic,
		st.streamID,
		int64(float64(initialCredit)*GrantImmediateFraction),
	)
}

// teardown releases per-stream resources that must not outlive the
// stream itself: the grantDebouncer, which flushes what Receive recorded and
// leaves the shared watchdog. Idempotent: every termination path calls it
// (Close, Reset, overrun, handleClose, handleReset, the OpenStream rollback),
// from the readLoop and from application goroutines. It leaves the receive
// side alone, since closeRecvOnce ends that: after Close, which ends only this
// side's sending, a message the peer sends still reaches Receive.
func (st *tcpStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
}

// tcpDeliveryQueueCapacity is the capacity of a tcpStream's delivery queue
// (recvCh): the most whole messages its consumer can leave unread before the
// next one ends the stream through overrun. It is twice recvChCapacity's
// per-stream-type count, the same bound noiseStream.enqueueControl puts on the
// control frames no credit paces: a byte-stream session's DATA is paced by no
// credit either (Send ignores its window).
func tcpDeliveryQueueCapacity(streamID uint64) int {
	return 2 * recvChCapacity(streamID)
}

// enqueueDelivery puts one whole in-order message on the stream's delivery
// queue (recvCh) without waiting: the readLoop (deliverToStream) calls it, and
// the readLoop also answers PING and serves the control plane and every other
// stream, so it never waits on one stream's consumer. It returns true when the
// message is queued for Receive. It returns false in two cases. The receive
// side has already ended (recvEnded: the peer's CLOSE or RESET, this side's
// Reset or overrun), so the message is one the peer sent after its own end or
// after this side's RESET, which tells the peer the stream is gone. Or the
// queue is full, holding tcpDeliveryQueueCapacity messages the consumer has
// not read: the stream ends through overrun, which refuses this message and
// every later one with a RESET the sender reads as aether.ErrStreamOverrun,
// while the consumer still reads every message queued ahead of it. A stream
// that goes on loses no message: a byte-stream session's sender holds no
// credit that would stop it short of the queue (Send ignores its window), so
// the refusal is how the queue's bound reaches the sender.
func (st *tcpStream) enqueueDelivery(payload []byte) bool {
	if st.recvEnded.Load() {
		return false
	}
	select {
	case st.recvCh <- payload:
		st.session.deliveryStats.recordDelivered(st.streamID)
		return true
	default:
	}
	st.overrun(len(payload))
	return false
}

// overrun ends a stream whose delivery queue is full when the readLoop has one
// more message for it (enqueueDelivery). It counts that message as having met
// a full queue and as dropped (DeliveryStats, which the consumer summing a
// session's stats reads), records aether.ErrStreamOverrun as the stream's end,
// writes the peer RESET(ResetFlowCtrl), which the peer's handleReset reads as
// aether.ErrStreamOverrun, takes the stream out of the session (sendReset),
// and ends the receive side, so Receive returns every message recvCh holds and
// then aether.ErrStreamOverrun. It runs on the readLoop, whose RESET write is
// the same kind of write as its PONG and its refusal RESET (registerStream).
// No abuse is charged: an honest sender reaches it by sending faster than the
// consumer reads.
func (st *tcpStream) overrun(n int) {
	s := st.session
	s.deliveryStats.recordBackpressure(st.streamID)
	s.deliveryStats.recordDropped(st.streamID, n)
	st.setEnd(aether.ErrStreamOverrun)
	dbgTCP.Printf("enqueueDelivery: stream %d delivery queue full (%d unread), resetting with ResetFlowCtrl",
		st.streamID, len(st.recvCh))
	st.teardown()
	_ = st.sendReset(aether.ResetFlowCtrl)
	st.closeRecvOnce()
}

// sendReset moves the stream to reset, writes RESET(reason) to the peer and
// takes the stream out of the session: the scheduler and the stream GC
// (releaseStream), s.streams when this stream object is the one there (a
// later stream under the same ID stays), and both directional compressors'
// per-stream state, an unbounded map (codec_short.go Compressor.streams) that
// otherwise only the peer-driven handleClose and handleReset prune. Reset,
// the funnel for every local teardown (a direct Reset, the stream GC's idle
// reap, the acceptor's close), and overrun call it; it returns the RESET
// write's error.
func (st *tcpStream) sendReset(reason aether.ResetReason) error {
	s := st.session
	st.state.Transition(aether.EventSendReset)
	payload := aether.EncodeReset(reason)
	err := s.writeFrame(&aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})
	s.releaseStream(st.streamID)
	s.mu.Lock()
	if cur, ok := s.streams[st.streamID]; ok && cur == st {
		delete(s.streams, st.streamID)
	}
	s.mu.Unlock()
	s.txCompressor.RemoveStream(st.streamID)
	s.rxCompressor.RemoveStream(st.streamID)
	return err
}

// NewTCPSession creates an Aether session over a TCP-family connection.
// `proto` must identify the underlying transport (ProtoTCP,
// ProtoWebSocket, ProtoGRPC) — WebSocket and gRPC share TCP's framing
// logic but need their own Protocol() identifier for capability
// reporting.
//
// Always takes SessionOptions. Numeric zero-values (MaxConcurrentStreams,
// MaxFECGroups, SessionIdleTimeout, CongestionAlgo) fall back to
// documented defaults via aether.NormalizeSessionOptions. Boolean fields
// are honoured as-supplied — start from aether.DefaultSessionOptions()
// if you want compression / header compression / scheduler etc. enabled
// and only want to override specific fields.
//
// Protocol-agnostic capability parity with NoiseSession — the
// following honour opts end-to-end on TCP/WS/gRPC, matching the Noise
// adapter's behaviour:
//
//   - `FrameLogging` / `Compression` / `HeaderComp` — per-frame gated
//   - `MaxConcurrentStreams` — RESET(Refused) + `reportAbuse` on excess
//   - `SessionIdleTimeout` — background tick closes idle sessions
//   - `AbuseScoreCapable` — per-peer misbehaviour scoring + circuit
//     breaker via `SetAbuseScoreRegistry`
//   - `StreamGC` — idle stream auto-RESET after timeout
//
// The ticker goroutine (`housekeepingTick`) handles idle eviction +
// stream GC — a single ticker covers both so we don't accumulate one
// goroutine per concern.
func NewTCPSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, proto aether.Protocol, opts aether.SessionOptions) *TCPSession {
	opts = aether.NormalizeSessionOptions(opts)
	tc := aether.TransportClassForProtocol(proto)
	base := aether.NewBaseSession(localNodeID, remoteNodeID, proto)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	base.SetIdleTimeouts(opts.SessionIdleTimeout, aether.DefaultSessionIdleTimeout)
	s := &TCPSession{
		BaseSession:   base,
		conn:          conn,
		layout:        aether.DefaultStreamLayout(),
		opts:          opts,
		classDefaults: aether.DefaultsForClass(tc),
		streams:       make(map[uint64]*tcpStream),
		sched:         scheduler.NewScheduler(),
		connWindow:    flow.NewConnWindow(0),
		txCompressor:  aether.NewCompressor(), // encode-side state
		rxCompressor:  aether.NewCompressor(), // decode-side state
		tickStop:      make(chan struct{}),

		wireDone:       make(chan struct{}),
		prefaceWritten: make(chan struct{}),
		prefaceTimeout: wireVersionsPrefaceTimeout,
	}
	s.wireOffer, s.wireOfferErr = aether.LocalWireVersions(opts.WireVersions)
	// Per-peer abuse tracker — per-session registry by default,
	// overridable via SetAbuseScoreRegistry for cross-session scoring.
	// The tracker wraps the registry plus the threshold-breaker
	// GoAway + close hooks so reportAbuse stays a one-liner.
	s.abuseTracker = aether.NewAbuseTracker(
		abuse.New[aether.NodeID](abuse.DefaultConfig()),
		remoteNodeID,
		func(reason aether.GoAwayReason, msg string) error {
			return s.GoAway(context.Background(), reason, msg)
		},
		s.CloseWithError,
		dbgTCP.Printf,
	)
	// Per-StreamID accept dispatch + AcceptStream FIFO — shared
	// implementation in the root aether package. NonBlockingDrop: when the
	// FIFO is full the OPEN-frame handler drops the stream rather than hold
	// the readLoop, which runs handleOpen and handleImplicitOpen.
	s.acceptor = aether.NewStreamAcceptor(aether.StreamAcceptorConfig{
		Mode:      aether.NonBlockingDrop,
		Closed:    base.CloseSignal(),
		ErrClosed: aether.ErrSessionClosed,
	})
	// Stream GC — identical policy to Noise; exempts well-known stream
	// IDs 0-3 (control / keepalive).
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(streamID uint64) {
		dbgTCP.Printf("StreamGC: resetting idle stream %d", streamID)
		s.mu.Lock()
		st, ok := s.streams[streamID]
		s.mu.Unlock()
		if !ok {
			return
		}
		// st.Reset deletes from s.streams, ends the receive side, releaseStream.
		_ = st.Reset(aether.ResetTimeout)
	})
	go s.streamGC.Start()

	// Clear any deadline the transport left armed on the conn during its
	// dial/handshake phase. Two known leak sources, both landing here:
	//   - WebSocket dial: gobwas/ws applies the dial context's deadline
	//     to the socket for the handshake and never clears it (the hijack
	//     dial in websocket/transport.go clears its own), so the socket
	//     carries the dialler's context deadline into the session.
	//   - WebSocket/TLS accept: a hijacked HTTP connection keeps whatever
	//     Read/Idle timeout the serving http.Server armed on it.
	// A TCPSession is long-lived and owns its liveness via the keepalive
	// stream + housekeepingTick idle eviction — readLoop blocks
	// indefinitely by design. A leftover deadline fires mid-session and
	// kills it at the dialler's context deadline (gobwas/ws leaves it armed
	// on the socket). Cleared once here, at the
	// single chokepoint every stream transport (WebSocket, TLS) funnels
	// through, so no transport can leak a deadline into a live session.
	_ = conn.SetDeadline(time.Time{})

	// The preface is the first thing written. Every frame write holds
	// writeMu, so taking it here and releasing it in writePreface, once the
	// preface write returns, orders the preface ahead of any frame whichever
	// goroutine writes first.
	s.writeMu.Lock()
	s.wireTimer = time.AfterFunc(s.prefaceTimeout, func() {
		if s.finishWireVersions(aether.NegotiatedWireVersions{}, errWireVersionsPrefaceTimeout) {
			s.CloseWithError(errWireVersionsPrefaceTimeout)
		}
	})
	go s.writePreface()
	go s.readLoop()
	go s.writeLoop()
	go s.housekeepingTick()
	return s
}

// writePreface writes this session's wire version preface, then releases
// the writeMu NewTCPSession took. A malformed local offer writes nothing.
// A failed write ends the exchange, if it is still open, and closes the
// session. writeMu is released before any close so the close path's own
// frame writes cannot wait on it.
func (s *TCPSession) writePreface() {
	err := s.wireOfferErr
	if err == nil {
		err = aether.WriteWireVersionsPreface(s.conn, s.wireOffer)
		if err != nil {
			err = fmt.Errorf("wire versions preface write: %w", err)
		}
	}
	s.writeMu.Unlock()
	close(s.prefaceWritten)
	if err != nil {
		s.finishWireVersions(aether.NegotiatedWireVersions{}, err)
		s.CloseWithError(err)
	}
}

// readPreface reads the peer's preface (bounded by
// aether.ReadWireVersionsPreface and wireVersionsPrefaceTimeout) and makes
// the choice from the two offers. It runs at the head of readLoop, so on a
// refusal no frame has been decoded and no stream exists.
func (s *TCPSession) readPreface() error {
	if s.wireOfferErr != nil {
		return s.wireOfferErr
	}
	peer, err := aether.ReadWireVersionsPreface(s.conn)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("wire versions preface: %w", err)
	}
	chosen, err := aether.ChooseWireVersions(s.wireOffer, peer)
	if err != nil {
		return err
	}
	// The grammar is set before readLoop decodes the peer's first frame,
	// which follows its preface on the conn, and before this side's writers
	// can choose a short form.
	s.rxCompressor.UseWireVersions(chosen)
	s.txCompressor.UseWireVersions(chosen)
	fragmentVersion, _ := chosen.Version(aether.WireVersionFragment)
	s.fragRecv = NewFragmentReceiver(fragmentVersion, 0, false, s.RemotePeerID())
	if !s.finishWireVersions(chosen, nil) {
		// The deadline or a close ended the exchange first.
		if r := s.wireResult.Load(); r != nil && r.err != nil {
			return r.err
		}
		return aether.ErrSessionClosed
	}
	return nil
}

// finishWireVersions records the outcome of the preface exchange once and
// releases everything waiting on wireDone. It reports whether this call was
// the one that ended the exchange.
func (s *TCPSession) finishWireVersions(chosen aether.NegotiatedWireVersions, err error) bool {
	first := false
	s.wireOnce.Do(func() {
		first = true
		s.wireResult.Store(&tcpWireResult{chosen: chosen, err: err})
		if s.wireTimer != nil {
			s.wireTimer.Stop()
		}
		close(s.wireDone)
	})
	return first
}

// awaitWireVersions blocks until the preface exchange has ended, returning
// its refusal, the caller's context error, or ErrSessionClosed. OpenStream
// calls it before creating any stream state.
func (s *TCPSession) awaitWireVersions(ctx context.Context) error {
	select {
	case <-s.wireDone:
	case <-s.CloseSignal():
		if err := s.wireRefusal(); err != nil {
			return err
		}
		return aether.ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	if r := s.wireResult.Load(); r.err != nil {
		return r.err
	}
	return nil
}

// wireRefusal returns why the preface exchange produced no set, or nil when
// it chose one or the session was simply closed. AcceptStream and
// AcceptStreamByID return it in place of the acceptor's ErrSessionClosed so
// a caller sees the mismatch that closed the session.
func (s *TCPSession) wireRefusal() error {
	if r := s.wireResult.Load(); r != nil && r.err != nil && r.err != aether.ErrSessionClosed {
		return r.err
	}
	return nil
}

// WireVersions returns the set the preface exchange chose. It waits for the
// exchange to end, which wireVersionsPrefaceTimeout bounds, and returns the
// empty set for a session that refused its peer or closed first.
func (s *TCPSession) WireVersions() aether.NegotiatedWireVersions {
	select {
	case <-s.wireDone:
	case <-s.CloseSignal():
	}
	if r := s.wireResult.Load(); r != nil {
		return r.chosen
	}
	return aether.NegotiatedWireVersions{}
}

// readLoop reads Aether frames from the TCP connection and dispatches to streams.
// Delegates the per-byte decode + short/full/batch dispatch to
// aether.ReadNextFrame so the Noise and TCP adapters share one decode
// implementation. Adapter-specific responsibilities stay here:
// structural validation gate + abuse-on-malformed + per-frame logging.
func (s *TCPSession) readLoop() {
	// exitErr carries the real ReadNextFrame failure (or nil on clean
	// EOF) into the deferred CloseWithError, so [SESSION-CLOSE]
	// reason= surfaces the actual transport/decode error instead of a
	// generic "readLoop exited" placeholder that masked the cause.
	var exitErr error
	defer func() { s.CloseWithError(exitErr) }()
	if err := s.readPreface(); err != nil {
		dbgTCP.Printf("readLoop: preface refused err=%v remote=%s", err, s.RemoteNodeID().Short())
		s.finishWireVersions(aether.NegotiatedWireVersions{}, err)
		// Let this side's own preface reach the peer before the conn closes,
		// so the peer reads both offers and reaches the same refusal rather
		// than a bare end of stream.
		select {
		case <-s.prefaceWritten:
		case <-s.CloseSignal():
		case <-time.After(s.prefaceTimeout):
		}
		exitErr = err
		return
	}
	for {
		frame, _, batch, err := aether.ReadNextFrame(s.conn, s.rxCompressor) // decode-side state
		if err != nil {
			dbgTCP.Printf("readLoop: EXIT err=%v remote=%s", err, s.RemoteNodeID().Short())
			if err != io.EOF {
				s.SetCloseErr(err)
				exitErr = err
			}
			return
		}
		if batch != nil {
			for _, f := range batch {
				// Batched sub-frames are decoded by the short-header
				// decoders (codec_short.go), which skip
				// Frame.Validate() — the same gap the single-frame path
				// guards below. Without a per-sub-frame gate a peer could
				// smuggle unknown Type bytes, oversize Length, or
				// payload/length mismatches into dispatchFrame inside a
				// 0x85 batch AND evade the ReasonMalformedFrame abuse
				// signal. Cross-adapter parity with the Noise adapter's
				// processIncomingFrame batch loop.
				if err := f.Validate(); err != nil {
					dbgTCP.Printf("readLoop: batch sub-frame validate failed: %v", err)
					s.reportAbuse(abuse.ReasonMalformedFrame)
					continue
				}
				s.Health().RecordActivity()
				s.dispatchFrame(f)
			}
			continue
		}

		// Structural validation gate — short-header decoders skip
		// Frame.Validate(), so without this check a peer could slip
		// frames with unknown Type bytes or oversize Length straight
		// into the dispatch switch. Cross-adapter parity with the
		// Noise adapter's processIncomingFrame.
		if err := frame.Validate(); err != nil {
			dbgTCP.Printf("readLoop: frame validate failed: %v", err)
			s.reportAbuse(abuse.ReasonMalformedFrame)
			continue
		}

		s.Health().RecordActivity()
		dbgTCP.Printf("readLoop: RX type=%d stream=%d len=%d flags=0x%02x", frame.Type, frame.StreamID, frame.Length, frame.Flags)
		s.dispatchFrame(frame)
	}
}

// dispatchFrame routes an incoming frame to the appropriate stream.
func (s *TCPSession) dispatchFrame(frame *aether.Frame) {
	// Record stream activity for GC — any frame type counts as
	// activity on its stream (OPEN/DATA/CLOSE/RESET/WINDOW/etc.). This
	// keeps the idle-timeout reset even on control-only flows like
	// keepalive.
	if s.streamGC != nil && frame.StreamID != 0 {
		s.streamGC.RecordActivity(frame.StreamID)
	}
	switch frame.Type {
	case aether.TypeOPEN:
		s.handleOpen(frame)
	case aether.TypeDATA:
		s.deliverToStream(frame)
	case aether.TypeCLOSE:
		s.handleClose(frame)
	case aether.TypeRESET:
		s.handleReset(frame)
	case aether.TypeWINDOW:
		s.handleWindowUpdate(frame)
	case aether.TypePING:
		s.handlePing(frame)
	case aether.TypePONG:
		s.handlePong(frame)
	case aether.TypeGOAWAY:
		s.handleGoAway(frame)
	case aether.TypeACK:
		// TCP provides native reliability — ACK not used
	case aether.TypePRIORITY:
		s.handlePriority(frame)
	case aether.TypeCONGESTION:
		s.handleCongestion(frame)
	}
}

func (s *TCPSession) deliverToStream(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok {
		// Implicit open via SYN flag in DATA
		if frame.Flags.Has(aether.FlagSYN) {
			s.handleImplicitOpen(frame)
			return
		}
		dbgTCP.Printf("deliverToStream: no stream for ID=%d, dropping %d bytes", frame.StreamID, frame.Length)
		return // unknown stream, drop
	}
	// A fragment is never delivered as message bytes: the session has no
	// realm, so the buffer refuses it, and the bytes the sender charged for it
	// are granted back at once.
	if frame.IsFragment() {
		if st.fragBuf == nil {
			st.fragBuf = NewFragmentBuffer() // a stream built outside the open paths
		}
		_, released, err := st.fragBuf.Add(s.fragRecv, st.streamID, frame.Payload)
		releaseCredit(st.window, released, st.streamID, s.sendWindowUpdateAgnostic)
		dbgTCP.Printf("deliverToStream: stream %d fragment refused: %v", frame.StreamID, err)
		return
	}
	// Queue the payload for the stream's consumer without waiting
	// (enqueueDelivery), so a slow consumer on this stream never holds the
	// readLoop, which keeps serving gossip, keepalive, control and every other
	// stream; a full queue ends this stream with a typed reset instead. A
	// stream whose receive side ended between the lookup above and this call
	// (a Reset on another goroutine) refuses the payload, since nothing closes
	// recvCh under this send.
	accepted := st.enqueueDelivery(frame.Payload)
	if accepted {
		// ACK-observe: track metrics (no wire ACK, no retransmit). Runs only
		// on the readLoop, so localSeq stays single-threaded.
		if st.observe != nil {
			seqNo := frame.SeqNo
			if seqNo == 0 {
				st.localSeq++
				seqNo = st.localSeq
			}
			st.observe.RecordReceive(seqNo, len(frame.Payload), time.Now())
		}
		if frame.StreamID == 0 {
			dbgTCP.Printf("deliverToStream: enqueued %d bytes for stream 0 (gossip)", len(frame.Payload))
		}
	} else {
		dbgTCP.Printf("deliverToStream: refused frame for stream %d (%d bytes, receive side ended or delivery queue full)", frame.StreamID, len(frame.Payload))
	}
}

// sendWindowUpdateAgnostic adapts sendWindowUpdate to the WindowUpdater signature.
func (s *TCPSession) sendWindowUpdateAgnostic(streamID uint64, credit uint64) {
	s.sendWindowUpdate(streamID, credit)
}

// sendWindowUpdate sends a WINDOW_UPDATE frame granting additional credit to the sender.
func (s *TCPSession) sendWindowUpdate(streamID uint64, credit uint64) {
	dbgTCP.Printf("WINDOW_UPDATE send stream=%d credit=%d", streamID, credit)
	if err := s.writeFrame(aether.BuildWindowUpdateFrame(s.LocalPeerID(), s.RemotePeerID(), streamID, credit)); err != nil {
		dbgTCP.Printf("WINDOW_UPDATE send FAILED stream=%d credit=%d err=%v", streamID, credit, err)
	}
}

// registerStream performs an atomic check-and-insert for a freshly-constructed
// tcpStream. When enforceRemoteCap is true and MaxConcurrentStreams would be
// exceeded, sends RESET(ResetRefused) and returns nil — the caller drops the
// frame. The check and the map write happen under a single s.mu.Lock so
// concurrent peer OPENs cannot race past the cap. Each refusal counts in
// streamRefused and charges abuse.ReasonStreamRefused.
func (s *TCPSession) registerStream(st *tcpStream, enforceRemoteCap bool) *tcpStream {
	s.mu.Lock()
	if existing, ok := s.streams[st.streamID]; ok {
		s.mu.Unlock()
		return existing // duplicate peer OPEN for open stream — return existing
	}
	// MaxConcurrentStreams cap applies to BOTH locally-initiated and
	// peer-initiated stream opens. enforceRemoteCap=true means
	// peer-initiated → on refusal, send a RESET so the peer gives up;
	// enforceRemoteCap=false means locally-initiated → return nil and
	// let the caller surface ErrStreamCapExhausted.
	{
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = DefaultTCPMaxConcurrentStreams
		}
		if len(s.streams) >= cap {
			s.mu.Unlock()
			atomic.AddUint64(&s.streamRefused, 1)
			s.reportAbuse(abuse.ReasonStreamRefused)
			if enforceRemoteCap {
				payload := aether.EncodeReset(aether.ResetRefused)
				reset := &aether.Frame{
					SenderID:   s.LocalPeerID(),
					ReceiverID: s.RemotePeerID(),
					StreamID:   st.streamID,
					Type:       aether.TypeRESET,
					Length:     uint32(len(payload)),
					Payload:    payload,
				}
				s.writeFrame(reset)
			}
			return nil
		}
	}
	s.streams[st.streamID] = st
	s.mu.Unlock()
	// Register with stream GC for idle-timeout tracking — only after
	// the cap check + map insert succeed.
	if s.streamGC != nil {
		s.streamGC.Register(st.streamID)
	}
	return st
}

// unregisterStream undoes registerStream — removes the stream from the
// session map and the GC tracker. Paired rollback for OpenStream's
// commit/rollback flow when a post-registration step (writeFrame, etc.)
// fails. Idempotent; safe to call even if the stream was never inserted.
func (s *TCPSession) unregisterStream(streamID uint64) {
	s.mu.Lock()
	delete(s.streams, streamID)
	s.mu.Unlock()
	s.releaseStream(streamID)
}

// StreamRefusedCount returns the number of peer-initiated stream opens
// rejected because MaxConcurrentStreams was reached.
func (s *TCPSession) StreamRefusedCount() uint64 {
	return atomic.LoadUint64(&s.streamRefused)
}

func (s *TCPSession) handleOpen(frame *aether.Frame) {
	dbgTCP.Printf("handleOpen: stream=%d", frame.StreamID)
	// The payload's InitialCredit is not read: on a byte-stream session the
	// transport owns flow control, and the window built below makes no send
	// decision.
	payload := aether.DecodeOpenPayload(frame.Payload)
	candidate := &tcpStream{
		streamID: frame.StreamID,
		config: aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		},
		session:  s,
		state:    aether.NewStreamStateMachine(),
		recvCh:   make(chan []byte, tcpDeliveryQueueCapacity(frame.StreamID)),
		recvDone: make(chan struct{}),
		fragBuf:  NewFragmentBuffer(),
		window:   flow.NewStreamWindowWithCap(0, 0),
		observe:  reliability.NewObserveEngine(),
	}
	st := s.registerStream(candidate, true /* enforceRemoteCap */)
	if st == nil {
		dbgTCP.Printf("handleOpen: refused stream=%d (cap reached)", frame.StreamID)
		return
	}
	// registerStream returns the pre-existing stream on duplicate OPEN;
	// only advance state + notify acceptor when we actually inserted.
	// Duplicate OPENs short-circuit here so the same stream is never
	// delivered twice to a waiter / acceptCh.
	if st != candidate {
		return
	}
	st.attachGrantDebouncer()
	st.state.Transition(aether.EventRecvOpen)

	s.sched.Register(frame.StreamID, payload.Priority, payload.Dependency)

	s.notifyStreamAccepted(st)
}

// notifyStreamAccepted hands a freshly-accepted stream to the shared
// StreamAcceptor. The acceptor picks between a pinned ByID waiter, a
// per-ID backlog slot, or the internal FIFO that AcceptStream drains.
// Called by handleOpen and handleImplicitOpen — the two paths that
// produce a remotely-initiated stream.
func (s *TCPSession) notifyStreamAccepted(st *tcpStream) {
	s.acceptor.Notify(st)
}

func (s *TCPSession) handleImplicitOpen(frame *aether.Frame) {
	// Decode the OPEN payload from the SYN-flagged DATA frame for proper stream config.
	// Falls back to defaults if the payload is missing or malformed.
	var cfg aether.StreamConfig
	if len(frame.Payload) > 0 {
		payload := aether.DecodeOpenPayload(frame.Payload)
		cfg = aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		}
	} else {
		cfg = aether.DefaultStreamConfig(frame.StreamID)
	}

	candidate := &tcpStream{
		streamID: frame.StreamID,
		config:   cfg,
		session:  s,
		state:    aether.NewStreamStateMachine(),
		recvCh:   make(chan []byte, tcpDeliveryQueueCapacity(frame.StreamID)),
		recvDone: make(chan struct{}),
		fragBuf:  NewFragmentBuffer(),
		window:   flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:  reliability.NewObserveEngine(),
	}
	st := s.registerStream(candidate, true /* enforceRemoteCap */)
	if st == nil {
		dbgTCP.Printf("handleImplicitOpen: refused stream=%d (cap reached)", frame.StreamID)
		return
	}
	if st != candidate {
		return
	}
	st.attachGrantDebouncer()
	st.state.Transition(aether.EventRecvData)

	// Propagate cfg.LatencyClass — parity with the noise adapter so a
	// caller's explicit class isn't silently dropped to ClassBULK.
	// ClassUnset (zero value) → DefaultLatencyClass(streamID).
	classAccepted := cfg.LatencyClass
	if classAccepted == aether.ClassUnset {
		classAccepted = aether.DefaultLatencyClass(frame.StreamID)
	}
	s.sched.RegisterWithClass(frame.StreamID, cfg.Priority, cfg.Dependency, classAccepted)

	s.notifyStreamAccepted(st)
}

func (s *TCPSession) handleClose(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if !ok {
		s.mu.Unlock()
		s.txCompressor.RemoveStream(frame.StreamID) // both directional compressors hold per-stream state
		s.rxCompressor.RemoveStream(frame.StreamID)
		return
	}
	// Transition AND remove-from-map BEFORE releasing s.mu, so every lookup
	// after this one finds a fully closed stream gone. The messages queued
	// before this CLOSE stay in recvCh, and Receive returns them before
	// io.EOF; enqueueDelivery refuses whatever comes after closeRecvOnce below
	// (recvEnded), and recvCh is never closed under its send.
	st.state.Transition(aether.EventRecvFIN)
	fullyClosed := !st.state.IsOpen()
	if fullyClosed {
		delete(s.streams, frame.StreamID)
	}
	s.mu.Unlock()

	if fullyClosed {
		st.teardown()
		st.closeRecvOnce()
		s.releaseStream(frame.StreamID)
	}
	s.txCompressor.RemoveStream(frame.StreamID) // both directional compressors hold per-stream state
	s.rxCompressor.RemoveStream(frame.StreamID)
}

func (s *TCPSession) handleReset(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if ok {
		delete(s.streams, frame.StreamID)
	}
	s.mu.Unlock()
	s.txCompressor.RemoveStream(frame.StreamID) // both directional compressors hold per-stream state
	s.rxCompressor.RemoveStream(frame.StreamID)
	if ok {
		// The peer's reason is recorded first, so Receive (after the messages
		// recvCh holds) and Send name it: a refusal (the peer's registerStream
		// cap) as aether.ErrStreamRefused, the peer's full delivery queue
		// (overrun) as aether.ErrStreamOverrun. Every other reason ends the
		// stream as io.EOF.
		switch aether.DecodeReset(frame.Payload) {
		case aether.ResetRefused:
			st.setEnd(aether.ErrStreamRefused)
		case aether.ResetFlowCtrl:
			st.setEnd(aether.ErrStreamOverrun)
		}
		st.state.Transition(aether.EventRecvReset)
		st.teardown()
		st.closeRecvOnce()
		s.releaseStream(frame.StreamID)
	}
}

// releaseStream idempotently unregisters streamID from the scheduler
// and stream GC. Parity with NoiseSession.releaseStream — gives every
// teardown path one helper to call instead of duplicating the pair.
func (s *TCPSession) releaseStream(streamID uint64) {
	s.sched.Unregister(streamID)
	if s.streamGC != nil {
		s.streamGC.Unregister(streamID)
	}
}

// controlHandler returns a ControlFrameHandler bound to this session's
// scheduler, health monitor, conn-window and frame writer. The
// stream-window lookup acquires s.mu around the streams-map read.
// WakeScheduler is false because the TCP writeLoop runs on a 2 ms
// ticker rather than blocking on Consume, so no writer waits for a wake.
func (s *TCPSession) controlHandler() *aether.ControlFrameHandler {
	return &aether.ControlFrameHandler{
		HealthMon:         s.Health(),
		Sched:             s.sched,
		ConnWindow:        s.connWindow,
		Writer:            s.writeFrame,
		Sender:            s.LocalPeerID(),
		Receiver:          s.RemotePeerID(),
		KeepaliveStreamID: s.layout.Keepalive,
		WakeScheduler:     false,
		StreamWindowLookup: func(streamID uint64) *flow.StreamWindow {
			s.mu.Lock()
			st, ok := s.streams[streamID]
			s.mu.Unlock()
			if !ok {
				return nil
			}
			return st.window
		},
	}
}

func (s *TCPSession) handleWindowUpdate(frame *aether.Frame) {
	s.controlHandler().HandleWindowUpdate(frame)
}

func (s *TCPSession) handlePing(frame *aether.Frame) {
	s.controlHandler().HandlePing(frame)
}

func (s *TCPSession) handlePong(frame *aether.Frame) {
	s.controlHandler().HandlePong(frame)
}

func (s *TCPSession) handleGoAway(frame *aether.Frame) {
	aether.HandleGoAwayFrame(s.CloseWithError, s.RemoteNodeID().Short(), "TCP", frame)
}

func (s *TCPSession) handlePriority(frame *aether.Frame) {
	s.controlHandler().HandlePriority(frame)
}

// handleCongestion processes an explicit CONGESTION frame — the peer
// asking us to slow down. The session stores the hint in its throttle;
// send-path consumers can check before committing large payloads.
func (s *TCPSession) handleCongestion(frame *aether.Frame) {
	p := aether.HandleCongestionFrame(&s.throttle, frame)
	dbgTCP.Printf("CONGESTION recv severity=%d reason=%d backoff=%dms",
		p.Severity, p.Reason, p.BackoffMs)
}

// SendCongestion emits a CONGESTION frame to the peer. Used when this
// side detects local pressure (memory high, recvCh backlog, etc.) and
// wants the remote to back off before packets pile up.
func (s *TCPSession) SendCongestion(p aether.CongestionPayload) error {
	return s.writeFrame(aether.BuildCongestionFrame(s.LocalPeerID(), s.RemotePeerID(), p))
}

// Throttle exposes the session's congestion-throttle state. Callers
// (e.g. gossip scheduler) can consult RateFactor/ShouldStall before
// dispatching large sends.
func (s *TCPSession) Throttle() *aether.CongestionThrottle {
	return &s.throttle
}

// DeliveryStats exposes the session's receive-path delivery counters to
// the consumer that sums a session's stats; cross-adapter parity with
// NoiseSession.DeliveryStats. The
// returned pointer is stable for the session's lifetime — callers can
// sample Delivered / Dropped / Backpressure / BytesDropped via Load()
// at monitoring cadence without holding any session lock.
func (s *TCPSession) DeliveryStats() *DeliveryStats {
	return &s.deliveryStats
}

// writeLoop reads from the scheduler and writes frames to the TCP connection.
// When multiple frames are queued, they're batched into a single write (0x85).
// A short ticker (2ms) provides batching window — gives the scheduler a
// chance to accumulate frames for coalescing — but the loop also consumes
// the wake channel so it serves bursty traffic with minimal latency.
//
// Write-error tracking: consecutive non-temporary write failures past
// writeFailTolerance trigger CloseWithError so a dying TCP/WS conn
// can't burn CPU spinning forever. readLoop's natural EOF on the same
// conn would eventually kill the session too, but that's
// "eventually" — explicit fail-fast surfaces broken conns inside
// milliseconds. Temporary errors (i/o timeout, EAGAIN) reset the
// counter so a transient hiccup doesn't tear the session down.
func (s *TCPSession) writeLoop() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	wake := s.sched.WakeCh()
	var consecutiveWriteFailures int
	for {
		select {
		case <-s.CloseSignal():
			return
		case <-ticker.C:
		case <-wake:
		}

		frame, _ := s.sched.Dequeue()
		// isProbe is irrelevant for the TCP transport — TCP has its own
		// kernel-level flow control and aether's cwnd is not enforced
		// here. The signature is the scheduler's, kept consistent so a
		// single call site doesn't have to special-case Dequeue per
		// transport.
		if frame == nil {
			continue
		}

		// Check for batch opportunity — coalesce up to 16 queued frames.
		// Skip batching when the head frame is stream-0 (gossip): gossip
		// frames are already ~64KB max-size chunks, so batching gains
		// nothing in compression but extends the writeMu hold and HoL-
		// blocks stream-1 (RPC). Releasing writeMu after every gossip
		// frame lets stream-1 interleave instead of waiting for a 16-
		// frame snapshot burst to drain. Skipping stream-0 batching
		// gives per-frame fairness on the one shared writeMu; a
		// writeLoop per class would give the same without the per-frame
		// release.
		// A batch is itself a short form (0x85), so only a session whose
		// grammar has the short forms coalesces.
		if s.opts.HeaderComp && s.txCompressor.ShortForms() && frame.StreamID != 0 && s.sched.Len() > 0 {
			batch := []*aether.Frame{frame}
			for s.sched.Len() > 0 && len(batch) < 16 {
				next, _ := s.sched.Dequeue()
				if next == nil {
					break
				}
				batch = append(batch, next)
			}
			if len(batch) > 1 {
				s.writeMu.Lock()
				_, err := s.txCompressor.EncodeBatch(s.conn, batch) // encode-side state
				s.writeMu.Unlock()
				if err != nil {
					dbgTCP.Printf("writeLoop: batch err=%v count=%d", err, len(batch))
					if s.bumpWriteFailLocked(&consecutiveWriteFailures, err) {
						return
					}
				} else {
					consecutiveWriteFailures = 0
				}
				continue
			}
			// Only 1 frame — fall through to single write
			frame = batch[0]
		}

		if s.opts.FrameLogging || frame.StreamID == 0 {
			dbgTCP.Printf("writeLoop: TX stream=%d type=%d seq=%d len=%d",
				frame.StreamID, frame.Type, frame.SeqNo, frame.Length)
		}
		if err := s.writeFrame(frame); err != nil {
			dbgTCP.Printf("writeLoop: writeFrame err=%v stream=%d", err, frame.StreamID)
			if s.bumpWriteFailLocked(&consecutiveWriteFailures, err) {
				return
			}
		} else {
			consecutiveWriteFailures = 0
		}
	}
}

// writeFailTolerance bounds how many consecutive non-temporary write
// failures writeLoop tolerates before tearing down the session. Picked
// to ride out a small burst of transient errors (rebind, ARP refresh)
// without sacrificing fail-fast on a genuinely broken conn — 5 attempts
// at ~2 ms tick interval is ~10 ms before close.
const writeFailTolerance = 5

// bumpWriteFailLocked increments the per-session consecutive failure
// counter. Returns true when writeLoop should exit (session closed via
// CloseWithError). Returns false for transient errors (caller resets
// counter via the normal success path).
//
// "Locked" in the name refers to the writeLoop's exclusive ownership of
// consecutiveWriteFailures — not a mutex; the counter is goroutine-local
// to writeLoop.
func (s *TCPSession) bumpWriteFailLocked(counter *int, err error) bool {
	if isTemporaryNetError(err) {
		return false
	}
	*counter++
	if *counter < writeFailTolerance {
		return false
	}
	s.CloseWithError(fmt.Errorf("write loop: %d consecutive failures (%w)", *counter, err))
	return true
}

// isTemporaryNetError returns true when err is a net.Error whose
// Temporary() reports true. Such errors should NOT count against the
// write-fail tolerance budget (kernel-level transient like EAGAIN or
// i/o timeout).
func isTemporaryNetError(err error) bool {
	if err == nil {
		return false
	}
	type temp interface{ Temporary() bool }
	if t, ok := err.(temp); ok && t.Temporary() {
		return true
	}
	return false
}

// writeFrame serializes and writes a single frame to the TCP connection.
// With opts.HeaderComp it takes a short form when the TX Compressor admits
// one, which it does only on a session whose chosen set has frame.short.
func (s *TCPSession) writeFrame(frame *aether.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.opts.HeaderComp {
		// All encoding goes through the TX-side compressor state (txCompressor).
		// Control frames: PING/PONG/CLOSE/RESET → 4 bytes
		if s.txCompressor.ShouldCompressControl(frame) {
			_, err := s.txCompressor.EncodeControlShort(s.conn, frame)
			return err
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.txCompressor.ShouldCompressACK(frame) {
			_, err := s.txCompressor.EncodeACKShort(s.conn, frame)
			return err
		}
		// DATA frames → 6-9 bytes
		if s.txCompressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				_, err := s.txCompressor.EncodeDataShortVar(s.conn, frame)
				return err
			}
			_, err := s.txCompressor.EncodeDataShort(s.conn, frame)
			return err
		}
	}

	// Full frame: discriminator and 50-byte header.
	_, err := aether.EncodeFrame(s.conn, frame)
	if err == nil {
		s.txCompressor.RecordFullHeader(frame) // encode-side state
	}
	return err
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface implementation
// ────────────────────────────────────────────────────────────────────────────

func (s *TCPSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		if err := s.wireRefusal(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("session closed")
	default:
	}
	// No stream exists before the wire versions are chosen: a refused peer
	// returns the refusal here and the session holds nothing to tear down.
	if err := s.awaitWireVersions(ctx); err != nil {
		return nil, err
	}

	st := &tcpStream{
		streamID: cfg.StreamID,
		config:   cfg,
		session:  s,
		state:    aether.NewStreamStateMachine(),
		recvCh:   make(chan []byte, tcpDeliveryQueueCapacity(cfg.StreamID)),
		recvDone: make(chan struct{}),
		fragBuf:  NewFragmentBuffer(),
		window:   flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:  reliability.NewObserveEngine(),
	}
	st.state.Transition(aether.EventSendOpen)

	// Locally-initiated open. registerStream(false) enforces the
	// MaxConcurrentStreams cap but skips the peer-side RESET. Surface
	// the typed sentinel ErrStreamCapExhausted so pool/dispatch
	// callers can detect cap-hit via errors.Is and back off rather
	// than closing the session.
	// registerStream has a tri-state return — nil on cap-hit, the
	// PRE-EXISTING stream when cfg.StreamID is still live in s.streams
	// (duplicate), or st on a fresh insert. A duplicate must not proceed
	// with the detached, never-mapped st: the rollback defer below would
	// delete the live map entry, RegisterWithClass would overwrite its
	// scheduler slot, and inbound DATA would route to the original stream
	// while the returned st.recvCh hangs forever. Compare identity and
	// error out — matching handleOpen's `st != candidate` guard — BEFORE
	// the rollback defer is armed so no cleanup touches the pre-existing
	// stream.
	registered := s.registerStream(st, false)
	if registered == nil {
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = DefaultTCPMaxConcurrentStreams
		}
		return nil, fmt.Errorf("OpenStream cap=%d: %w", cap, aether.ErrStreamCapExhausted)
	}
	if registered != st {
		// Duplicate still-live StreamID (e.g. a pool recycling an ID
		// before the prior stream closed). The pre-existing stream is
		// untouched; never return a detached, dead stream.
		return nil, fmt.Errorf("OpenStream stream=%d: %w", cfg.StreamID, aether.ErrDuplicateStreamID)
	}

	// committed flips to true after every post-registration step succeeds.
	// Until then, the deferred rollback unwinds every side-effect that
	// registerStream + attachGrantDebouncer + scheduler.Register + writeFrame
	// installed. A (nil, err) return that left the map entry, the GC and
	// scheduler registrations and the grantDebouncer goroutine in place would
	// leave a stream no caller holds in s.streams until the stream GC's idle
	// sweep resets it, counted against MaxConcurrentStreams by registerStream
	// the whole while.
	committed := false
	defer func() {
		if committed {
			return
		}
		st.teardown()
		s.unregisterStream(cfg.StreamID)
		st.closeRecvOnce()
	}()

	st.attachGrantDebouncer()

	// Propagate cfg.LatencyClass — parity with the noise adapter so a
	// caller's explicit class isn't silently dropped to ClassBULK.
	// ClassUnset (zero value) → DefaultLatencyClass(streamID).
	classOpen := cfg.LatencyClass
	if classOpen == aether.ClassUnset {
		classOpen = aether.DefaultLatencyClass(cfg.StreamID)
	}
	s.sched.RegisterWithClass(cfg.StreamID, cfg.Priority, cfg.Dependency, classOpen)

	// Implicit OPEN via SYN flag — saves 50 bytes by combining OPEN with first DATA frame.
	// The OPEN payload (reliability, priority, dependency) rides as the DATA frame's payload.
	// The remote's handleImplicitOpen decodes it to configure the stream properly.
	// Its InitialCredit is zero, the value that states no aether stream credit:
	// on a byte-stream session the transport owns flow control, the stream's
	// window makes no send decision (Send ignores TryConsume's result), and neither
	// handleOpen nor handleImplicitOpen reads the field.
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	})
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   cfg.StreamID,
		Type:       aether.TypeDATA,
		Flags:      aether.FlagSYN,
		Length:     uint32(len(openPayload)),
		Payload:    openPayload,
	}
	if err := s.writeFrame(frame); err != nil {
		return nil, fmt.Errorf("send SYN+DATA: %w", err)
	}

	committed = true
	return st, nil
}

// AcceptStream delegates to the shared aether.StreamAcceptor, which owns
// the FIFO channel and the per-StreamID dispatch for every adapter. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *TCPSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	dbgTCP.Printf("AcceptStream: waiting...")
	st, err := s.acceptor.Accept(ctx)
	if err == nil {
		if ts, ok := st.(*tcpStream); ok {
			dbgTCP.Printf("AcceptStream: got stream=%d", ts.streamID)
		}
	} else if werr := s.wireRefusal(); werr != nil {
		return nil, werr
	}
	return st, err
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so the Noise, TCP, and QUIC adapters share one
// implementation rather than each maintaining its own copy.
func (s *TCPSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	st, err := s.acceptor.AcceptByID(ctx, streamID)
	if err != nil {
		if werr := s.wireRefusal(); werr != nil {
			return nil, werr
		}
	}
	return st, err
}

// Identity / Capabilities / Protocol accessors are promoted from the
// embedded *BaseSession. Ping is below.

// Ping sends a PING frame and waits for inbound activity (PONG or any
// other frame) before reporting RTT. Delegates to
// aether.WaitForActivityPing for the polling loop — see that helper
// for the zombie-session detection rationale.
func (s *TCPSession) Ping(ctx context.Context) (time.Duration, error) {
	return aether.WaitForActivityPing(ctx, s.Health(), s.CloseSignal(), func(seqNo uint32) error {
		return s.writeFrame(&aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   s.layout.Keepalive,
			Type:       aether.TypePING,
			SeqNo:      seqNo,
		})
	})
}

func (s *TCPSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	return aether.SendGoAway(s.writeFrame, s.LocalPeerID(), s.RemotePeerID(), s.layout.Control, reason, message)
}

func (s *TCPSession) Close() error {
	return s.CloseWithError(nil)
}

func (s *TCPSession) CloseWithError(err error) error {
	if !s.SignalClose() {
		return nil
	}
	if err != nil {
		s.SetCloseErr(err)
	}
	// A close before the preface exchange ended ends it, releasing every
	// waiter and stopping the deadline timer.
	s.finishWireVersions(aether.NegotiatedWireVersions{}, aether.ErrSessionClosed)
	// Capture the caller chain so the FIRST closer in a close
	// cascade is identifiable. Frame 0 is this closure, 1 is
	// CloseWithError; frames 2-5 are the actual callers — readLoop
	// defer, stall detector, idle watchdog, the ORBTR dedup/multipath
	// layer, or transport accept-full.
	callerChain := aether.CaptureCallerChain(2, 4)
	// Log EVERY close, including a clean nil Close: the dedup/multipath
	// layer above closes a losing session with a nil error, and a log of
	// error closes alone would show only the readLoop-exit close that
	// follows on the peer, not the close that started the churn. The
	// callers= chain names whoever triggered the close.
	reason := "clean(nil)"
	if err != nil {
		reason = err.Error()
	}
	log.Printf("[SESSION-CLOSE] %s peer=%s reason=%q callers=%s",
		s.Protocol(), s.RemoteNodeID().Short(), reason, callerChain)
	if s.tickStop != nil {
		// Non-blocking close: housekeepingTick watches both this
		// and the BaseSession close-signal so either signal stops it.
		select {
		case <-s.tickStop:
		default:
			close(s.tickStop)
		}
	}
	if s.streamGC != nil {
		s.streamGC.Stop()
	}
	// Release any AcceptStreamByID waiters and unparked backlog
	// streams so blocked callers return ErrSessionClosed instead of
	// deadlocking. Backlog streams are reset because their config /
	// recvCh is otherwise orphaned — nobody else will ever pick
	// them up after close. The acceptor surfaces drained backlog
	// streams; the adapter calls Reset because the transport-
	// specific teardown lives here.
	if s.acceptor != nil {
		for _, st := range s.acceptor.Close() {
			_ = st.Reset(aether.ResetCancel)
		}
	}
	s.conn.Close()
	return nil
}

// housekeepingTick runs the protocol-agnostic periodic maintenance
// that NoiseSession's reliabilityTick does (minus the Noise-specific
// reliability work). Three concerns per tick:
//
//  1. **Idle session eviction** — session with no inbound activity for
//     `opts.SessionIdleTimeout` is closed so goroutines + memory are
//     reclaimed. Matches the Noise adapter's policy exactly.
//  2. **Flow-control auto-tune** — feeds the session's observed RTT
//     into each stream's window and applies a bounded window resize
//     based on `SuggestedWindow()`. Gated by AETHER_AUTOTUNE env var
//     (set to "off" to disable) so we can kill it in production if it
//     misbehaves.
//  3. **Keepalive nudge** — TCP relies on native keepalive which the
//     OS usually has tuned to hours; we don't reimplement it here,
//     but RecordActivity gets called on every incoming frame so the
//     idle check above stays accurate under real traffic.
//
// Runs on a 10s cadence — idle eviction is not latency-sensitive, and
// a 10s tick means we pay under ~1 µs/sec in aggregate. Exits on
// session close.
func (s *TCPSession) housekeepingTick() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.CloseSignal():
			return
		case <-s.tickStop:
			return
		case <-ticker.C:
			idle := s.opts.SessionIdleTimeout
			if idle <= 0 {
				idle = aether.DefaultSessionIdleTimeout
			}
			if time.Since(s.Health().LastActivity()) > idle {
				dbgTCP.Printf("session idle timeout (%s) — closing", idle)
				s.CloseWithError(fmt.Errorf("session idle timeout (%s)", idle))
				return
			}
			s.autoTuneWindows()
		}
	}
}

// autoTuneWindows feeds session RTT into each stream's window and applies
// a bounded resize based on SuggestedWindow. Called from housekeepingTick.
// Disabled when AETHER_AUTOTUNE=off. Safe to call concurrently with sends
// because GrowWindow/ShrinkWindow use the semaphore's own locks.
func (s *TCPSession) autoTuneWindows() {
	if aether.AutoTuneDisabled() {
		return
	}
	_, avgRTT := s.Health().RTT()
	if avgRTT <= 0 {
		return
	}
	s.mu.Lock()
	streams := make([]*tcpStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	for _, st := range streams {
		res := aether.AutoTuneWindow(st.window, avgRTT)
		switch res.Action {
		case "grow":
			if res.Applied > 0 {
				dbgTCP.Printf("autoTune stream=%d grow=%d current=%d rtt=%s",
					st.streamID, res.Applied, res.Current, avgRTT)
			}
		case "shrink":
			if res.Applied > 0 {
				dbgTCP.Printf("autoTune stream=%d shrink=%d current=%d rtt=%s",
					st.streamID, res.Applied, res.Current, avgRTT)
			}
		}
	}
}

// reportAbuse records a peer misbehaviour event. Delegates to the
// shared AbuseTracker, which handles the registry Record +
// threshold-breaker GoAway + close. Safe to call at high frequency —
// the decay model means transient events are forgiven.
func (s *TCPSession) reportAbuse(r abuse.Reason) {
	s.abuseTracker.Report(r)
}

// PeerAbuseScore returns the remote peer's current decayed score (0
// when no events recorded or when the tracker has no registry).
func (s *TCPSession) PeerAbuseScore() float64 {
	score, _ := s.abuseTracker.PeerScore()
	return score
}

// SetAbuseScoreRegistry swaps the per-session registry for a shared
// one — for cross-session operator dashboards. Signature takes
// `interface{}` to satisfy `aether.AbuseScoreCapable` without an
// import cycle; returns false when the registry type doesn't match.
func (s *TCPSession) SetAbuseScoreRegistry(r interface{}) bool {
	return s.abuseTracker.SetRegistry(r)
}

// LastActivity / IdleTimeout / IsClosed / ConnectionID / Health /
// Protocol / Capabilities all come from the embedded *BaseSession.

func (s *TCPSession) SessionKey() []byte      { return nil } // TLS provides encryption
func (s *TCPSession) CongestionWindow() int64 { return 0 }   // TCP handles congestion
func (s *TCPSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	observeData := make(map[uint64]aether.StreamObserveData, len(s.streams))
	for id, st := range s.streams {
		if st.observe != nil {
			m := st.observe.Metrics()
			observeData[id] = aether.StreamObserveData{
				PacketsReceived:      m.PacketsReceived,
				BytesReceived:        m.BytesReceived,
				HighestSeqNo:         m.HighestSeqNo,
				GapCount:             m.GapCount,
				ReorderCount:         m.ReorderCount,
				MaxReorderDistance:   m.MaxReorderDistance,
				LossEstimatePermille: m.LossEstimatePermille,
				JitterUs:             m.JitterUs,
			}
		}
	}
	s.mu.Unlock()
	return aether.SessionMetrics{
		RTT:           avg,
		ActiveStreams: streamCount,
		StreamObserve: observeData,
		// TCP/WS/gRPC have no reliability engine, so only StreamRefused
		// applies. Other security counters live on the Noise path.
		StreamRefused: s.StreamRefusedCount(),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// tcpStream — aether.Stream implementation
// ────────────────────────────────────────────────────────────────────────────

func (st *tcpStream) StreamID() uint64            { return st.streamID }
func (st *tcpStream) Config() aether.StreamConfig { return st.config }
func (st *tcpStream) IsOpen() bool                { return st.state.IsOpen() }

func (st *tcpStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.connView = NewStreamConn(st) })
	return st.connView
}

func (st *tcpStream) Send(ctx context.Context, data []byte) error {
	if !st.state.CanSend() {
		if st.streamID == 0 {
			dbgTCP.Printf("Send: stream 0 cannot send (state=%s)", st.state.State())
		}
		return st.endError(fmt.Errorf("stream %d: cannot send (state=%s)", st.streamID, st.state.State()))
	}

	// Flow control: TCP provides native backpressure, so we don't enforce
	// Aether-level credit limits on TCP/WS adapters. The non-blocking
	// TryConsume keeps the metrics — the blocking Consume could stall this
	// Send for the full ConsumeTimeout (~10s) on a drained window, against
	// the "TCP native backpressure only" intent. The send proceeds
	// regardless of the return.
	_ = st.window.TryConsume(int64(len(data)))

	totalLen := len(data)

	// A message keeps its boundary, arriving as one Receive(). The
	// fragment envelope that would split one larger than the class
	// MaxFrameSize into interleavable frames needs the session's realm, and a
	// TCPSession has none (fragRecv), so every message travels as one DATA
	// frame. The byte stream carries a frame of any length up to
	// aether.MaxPayloadSize, which the peer's ReadNextFrame also enforces; a
	// larger message fails loudly rather than ship truncated. A
	// message above MaxFrameSize holds the write loop for its whole length.
	// TODO: when a byte-stream session's identity binds a mesh realm, split a
	// message above MaxFrameSize with SplitMessage as NoiseSession does, so
	// other streams interleave with it.
	if totalLen > aether.MaxPayloadSize {
		return fmt.Errorf("stream %d: %w: %d bytes, one frame carries at most %d",
			st.streamID, ErrPayloadTooLarge, totalLen, aether.MaxPayloadSize)
	}
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeDATA,
		Length:     uint32(totalLen),
		Payload:    data,
	}
	st.session.sched.Enqueue(st.streamID, frame)

	if st.streamID == 0 {
		dbgTCP.Printf("Send: enqueued %d bytes for stream 0 (gossip), schedLen=%d", totalLen, st.session.sched.QueueLen(0))
	}
	return nil
}

// Receive returns the next whole message the readLoop queued on recvCh
// (enqueueDelivery). After closeRecvOnce has closed recvDone it still returns
// what recvCh holds, one message per call, and then the stream's end:
// io.EOF, or the typed reason endErr records (aether.ErrStreamOverrun,
// aether.ErrStreamRefused). The drain comes first because a select with both
// recvCh and recvDone ready picks either, and a message delivered before the
// CLOSE or RESET must not be lost behind the end. A stream built without
// recvDone reports the same end through its closed recvCh.
func (st *tcpStream) Receive(ctx context.Context) ([]byte, error) {
	consumed := func(data []byte) ([]byte, error) {
		// Consume-driven grant: record the app-consumed bytes in the
		// stream-level debouncer so WINDOW_UPDATE emission advances with
		// application progress, not frame-receipt. recvCh holds whole
		// messages only (deliverToStream keeps fragments out of it).
		if st.grantDebouncer != nil {
			st.grantDebouncer.Record(int64(len(data)))
		}
		return data, nil
	}
	for {
		select {
		case data, ok := <-st.recvCh:
			if !ok {
				return nil, st.endError(io.EOF)
			}
			return consumed(data)
		case <-st.recvDone:
			select {
			case data, ok := <-st.recvCh:
				if !ok {
					return nil, st.endError(io.EOF)
				}
				return consumed(data)
			default:
				return nil, st.endError(io.EOF)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-st.session.CloseSignal():
			return nil, fmt.Errorf("session closed")
		}
	}
}

func (st *tcpStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	st.teardown()
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeCLOSE,
	}
	return st.session.writeFrame(frame)
}

// Reset abandons the stream from this side: it stops the grantDebouncer,
// writes RESET(reason) and takes the stream out of the session (sendReset,
// which also frees the compressors' per-stream state the stream would
// otherwise hold for the session's life), then ends the receive side, after
// which Receive returns what recvCh holds and then the stream's end (io.EOF
// unless endErr records a typed reason). A direct Reset, the
// stream GC's idle reap and CloseWithError's reset of unaccepted streams all
// come here.
func (st *tcpStream) Reset(reason aether.ResetReason) error {
	st.teardown()
	err := st.sendReset(reason)
	st.closeRecvOnce()
	return err
}

func (st *tcpStream) SetPriority(weight uint8, dependency uint64) {
	st.session.sched.SetWeight(st.streamID, weight)
}

// AvailableCredit exposes the current send-side flow-control credit for
// this stream. Used by upper layers (gossip) to self-throttle against
// a near-empty window. TCP-family streams still track a window even though
// Send ignores timeouts — the value is accurate for scheduling decisions.
func (st *tcpStream) AvailableCredit() int64 {
	return st.window.Available()
}

// Ensure interfaces are satisfied at compile time.
var _ aether.Session = (*TCPSession)(nil)
var _ aether.AbuseScoreCapable = (*TCPSession)(nil)
var _ aether.IdleEvictable = (*TCPSession)(nil)
var _ aether.WireVersionsReporter = (*TCPSession)(nil)
var _ aether.Stream = (*tcpStream)(nil)

// Suppress unused import warnings for packages used in struct fields.
var _ = (*congestion.Controller)(nil)
