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

	// Per-session delivery-side flow-control telemetry. Cross-
	// adapter parity with NoiseSession.deliveryStats — every
	// DeliverToRecvChWithSignals call on this session points at this
	// shared DeliveryStats so receive-path delivery / drop /
	// backpressure / bytes-dropped counters are session-aggregate.
	// Surfaced through DeliveryStats() for the consumer that sums a
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
	// recvCh holds the whole messages deliverLoop has handed to the
	// application; Receive reads it. It is never closed: its end is recvDone,
	// which closeRecvOnce closes exactly once (recvOnce) and Receive selects
	// on, draining what recvCh still holds before it returns io.EOF. A close
	// of recvCh would race deliverLoop's send into it, since closeRecvOnce
	// runs on the readLoop (handleClose, handleReset) and on application
	// goroutines (Reset) while deliverLoop runs on its own. recvDone is made
	// in the struct literal with recvCh (handleOpen, handleImplicitOpen,
	// OpenStream); a stream built outside those paths has neither recvDone
	// nor deliverCh, and closeRecvOnce closes its recvCh instead.
	recvCh   chan []byte
	recvDone chan struct{}
	// deliverCh carries each in-order payload from the readLoop
	// (deliverToStream, through enqueueDelivery) to this stream's deliverLoop,
	// which performs the send into recvCh with its bounded backpressure off
	// the readLoop, so a slow consumer on one stream holds only its own
	// deliverLoop and the readLoop keeps serving every other stream. It is
	// never closed: its end is deliverDone, which teardown closes exactly once
	// (deliverOnce); enqueueDelivery and deliverLoop select on it. A close of
	// deliverCh would race enqueueDelivery's send, since teardown runs on
	// application goroutines (Close, Reset), the stream GC and CloseWithError
	// while the readLoop is still dispatching DATA for the stream. Both are
	// made in the struct literal before the stream is visible in s.streams;
	// deliverLoop is started by attachGrantDebouncer after registration
	// (deliverStartOnce).
	deliverCh        chan []byte
	deliverDone      chan struct{}
	deliverOnce      sync.Once // closes deliverDone exactly once
	deliverStartOnce sync.Once // starts deliverLoop exactly once
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
}

// closeRecvOnce ends the stream's receive side exactly once: it closes
// recvDone, on which Receive returns what recvCh still holds and then io.EOF.
// Every termination path calls it (handleClose, handleReset, Reset, the
// OpenStream rollback, the stream GC through Reset), from the readLoop and
// from application goroutines, so recvOnce keeps the close idempotent.
// recvCh itself is never closed here because deliverLoop may be sending into
// it on another goroutine; a stream built without recvDone (outside the open
// paths, with no deliverLoop) has its recvCh closed instead, which Receive
// reads as the same end.
func (st *tcpStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		if st.recvDone != nil {
			close(st.recvDone)
			return
		}
		close(st.recvCh)
	})
}

// attachGrantDebouncer initializes st.grantDebouncer bound to st.window
// and st.session.sendWindowUpdateAgnostic. Called after the stream is
// fully constructed + registered so the session back-reference is live.
// Safe to call once per stream; no-op if already attached.
func (st *tcpStream) attachGrantDebouncer() {
	if st.window == nil || st.session == nil {
		return
	}
	// Start the per-stream delivery goroutine. deliverCh and deliverDone come
	// from the struct literal, ahead of the stream's insertion into s.streams,
	// so the readLoop never reads a field being written here.
	// deliverStartOnce keeps a second attachGrantDebouncer from starting a
	// second deliverLoop, which would take payloads from deliverCh out of
	// order.
	if st.deliverCh != nil {
		st.deliverStartOnce.Do(func() { go st.deliverLoop() })
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
// stream itself. Idempotent: every termination path calls it (Close, Reset,
// handleClose, handleReset, the OpenStream rollback), from the readLoop and
// from application goroutines.
func (st *tcpStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
	// End delivery: closing deliverDone makes deliverLoop hand over what
	// deliverCh still holds and return, and makes enqueueDelivery drop what
	// the readLoop dispatches from now on. deliverCh is not closed because the
	// readLoop may be sending into it at this moment (enqueueDelivery). The
	// nil guard covers a stream built outside the open paths, which has no
	// deliverCh and no deliverLoop.
	if st.deliverDone != nil {
		st.deliverOnce.Do(func() { close(st.deliverDone) })
	}
}

// deliverLoop is the per-stream delivery goroutine: it takes each in-order
// payload the readLoop put on deliverCh and performs the send into recvCh,
// with the bounded backpressure DeliverToRecvChWithSignals applies, off the
// readLoop, so a slow application consumer holds only this goroutine while
// the readLoop keeps serving every other stream. It returns when teardown
// closes deliverDone, after handing over what deliverCh still holds, each
// payload within the same bound, so a message that arrived before a CLOSE
// reaches recvCh ahead of the end Receive reports. Nothing closes recvCh
// while this goroutine runs (closeRecvOnce closes recvDone), so the send
// never meets a closed channel.
func (st *tcpStream) deliverLoop() {
	s := st.session
	deliver := func(payload []byte) {
		// The drop accounting (credit grant, congestion signal) lives inside
		// DeliverToRecvChWithSignals' timeout path, so the bool is advisory.
		DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion, &s.deliveryStats)
	}
	for {
		select {
		case payload := <-st.deliverCh:
			deliver(payload)
		case <-st.deliverDone:
			for {
				select {
				case payload := <-st.deliverCh:
					deliver(payload)
				default:
					return
				}
			}
		}
	}
}

// enqueueDelivery hands one in-order payload to deliverLoop without
// blocking: the readLoop (deliverToStream) calls it and must never wait on a
// stream's consumer. It returns false when it does not hand the payload over:
// deliverCh is full (deliverCh and recvCh both saturated, a sustained
// overload), in which case the payload is dropped with the accounting
// DeliverToRecvChWithSignals' drop path uses (backpressure and dropped
// stats, stream-window grant, CONGESTION signal) so the sender is throttled
// and never stalls on lost credit; or the stream has been torn down
// (deliverDone closed), in which case the payload is dropped without
// accounting, since the stream's window and its peer's view of it end with
// the RESET or CLOSE teardown sent or received. deliverCh is never closed,
// so the send cannot meet a closed channel; selecting on deliverDone is what
// keeps a torn-down stream from filling its buffer and then signalling
// congestion for bytes no one will read.
//
// deliverCh is nil only for a stream built outside the open paths (no
// deliverLoop); that stream is delivered inline, without the readLoop
// isolation.
func (st *tcpStream) enqueueDelivery(payload []byte) bool {
	s := st.session
	if st.deliverCh == nil {
		return DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion, &s.deliveryStats)
	}
	select {
	case st.deliverCh <- payload:
		return true
	case <-st.deliverDone:
		return false
	default:
	}
	s.deliveryStats.recordBackpressure(st.streamID)
	dropGrantCredit(st.window, payload, st.streamID, s.sendWindowUpdateAgnostic)
	s.deliveryStats.recordDropped(st.streamID, len(payload))
	_ = s.SendCongestion(aether.CongestionPayload{Reason: aether.CongestionDownstream, Severity: 80, BackoffMs: 500})
	return false
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
	// Hand the payload to the per-stream deliverLoop without blocking rather
	// than perform the bounded backpressure inline on the shared readLoop: a
	// slow consumer on this stream then holds only its own deliverLoop, and
	// the readLoop keeps serving gossip, keepalive, control and ACK for every
	// other stream. A stream torn down between the lookup above and this call
	// (Reset on another goroutine) drops the payload here, since the queue's
	// end is a channel both sides select on and nothing is closed under this
	// send.
	accepted := st.enqueueDelivery(frame.Payload)
	if accepted {
		// ACK-observe: track metrics (no wire ACK, no retransmit). Runs on the
		// readLoop, so localSeq stays single-threaded (deliverLoop never
		// touches it).
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
		dbgTCP.Printf("deliverToStream: DROPPED frame for stream %d (%d bytes, deliverCh full or stream torn down)", frame.StreamID, len(frame.Payload))
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
	payload := aether.DecodeOpenPayload(frame.Payload)
	candidate := &tcpStream{
		streamID: frame.StreamID,
		config: aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		},
		session:     s,
		state:       aether.NewStreamStateMachine(),
		recvCh:      make(chan []byte, recvChCapacity(frame.StreamID)),
		recvDone:    make(chan struct{}),
		deliverCh:   make(chan []byte, recvChCapacity(frame.StreamID)),
		deliverDone: make(chan struct{}),
		fragBuf:     NewFragmentBuffer(),
		window:      flow.NewStreamWindowWithCap(0, 0),
		observe:     reliability.NewObserveEngine(),
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
		streamID:    frame.StreamID,
		config:      cfg,
		session:     s,
		state:       aether.NewStreamStateMachine(),
		recvCh:      make(chan []byte, recvChCapacity(frame.StreamID)),
		recvDone:    make(chan struct{}),
		deliverCh:   make(chan []byte, recvChCapacity(frame.StreamID)),
		deliverDone: make(chan struct{}),
		fragBuf:     NewFragmentBuffer(),
		window:      flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:     reliability.NewObserveEngine(),
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
	// Transition AND remove-from-map BEFORE releasing s.mu, so that any
	// concurrent deliverToStream which has not yet acquired s.mu sees the
	// deleted entry and drops the frame. A deliverToStream that already holds
	// st from a lookup before this lock hands its payload to enqueueDelivery,
	// which selects on deliverDone (closed by the teardown below, when the
	// stream is fully closed) beside its send on deliverCh, a channel nothing
	// closes: the payload is queued for deliverLoop's drain or dropped, and
	// the send never meets a closed channel.
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
		streamID:    cfg.StreamID,
		config:      cfg,
		session:     s,
		state:       aether.NewStreamStateMachine(),
		recvCh:      make(chan []byte, recvChCapacity(cfg.StreamID)),
		recvDone:    make(chan struct{}),
		deliverCh:   make(chan []byte, recvChCapacity(cfg.StreamID)),
		deliverDone: make(chan struct{}),
		fragBuf:     NewFragmentBuffer(),
		window:      flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:     reliability.NewObserveEngine(),
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
		return fmt.Errorf("stream %d: cannot send (state=%s)", st.streamID, st.state.State())
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

// Receive returns the next whole message deliverLoop handed to recvCh.
// After closeRecvOnce has closed recvDone it still returns what recvCh holds,
// one message per call, and then io.EOF; the drain comes first because a
// select with both recvCh and recvDone ready picks either, and a message
// delivered before the CLOSE or RESET must not be lost behind the end. A
// stream built without recvDone reports the same end through its closed
// recvCh.
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
				return nil, io.EOF
			}
			return consumed(data)
		case <-st.recvDone:
			select {
			case data, ok := <-st.recvCh:
				if !ok {
					return nil, io.EOF
				}
				return consumed(data)
			default:
				return nil, io.EOF
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

func (st *tcpStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	st.teardown()
	payload := aether.EncodeReset(reason)
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	err := st.session.writeFrame(frame)
	st.session.releaseStream(st.streamID)
	st.session.mu.Lock()
	if _, ok := st.session.streams[st.streamID]; ok {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
	// Free the per-stream compressor entry on local teardown. The compressor
	// keeps per-stream SeqNo state in a separate unbounded sync.Map
	// (codec_short.go Compressor.streams) that only the peer-driven handleClose
	// / handleReset paths prune. Reset is the funnel for every LOCAL teardown —
	// a direct Reset, the streamGC idle-reap callback, and the cancel path all
	// route here — so without this the entry leaks for the session lifetime on
	// locally-reset or GC-reaped streams. Ordering mirrors handleReset:
	// delete-from-streams, then RemoveStream. The compressor is split TX/RX,
	// so free the stream from BOTH directional instances.
	st.session.txCompressor.RemoveStream(st.streamID)
	st.session.rxCompressor.RemoveStream(st.streamID)
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
