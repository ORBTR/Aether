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
// See _SECURITY.md §3.12.
const DefaultTCPMaxConcurrentStreams = 256

// Per-StreamID backlog tuning constants moved to the root aether
// package (stream_acceptor.go) — they are shared with the Noise and
// QUIC adapters via the StreamAcceptor type rather than duplicated
// here. See aether.MaxByIDBacklogPerStream / aether.ByIDBacklogGrace.

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
	// AE-P-05: separate compressor state for TX (encode) vs RX (decode) so
	// cross-direction traffic never pollutes SessionCompState identity
	// (lastSender/lastReceiver) or a stream's lastSeqNo/frameCount. A single
	// shared instance flip-flopped the reconstructed identity with the
	// direction of the most recent full header and cross-incremented the
	// frameCount%64 resync cadence; splitting gives each directional flow
	// dedicated state that tracks identically on both peers.
	txCompressor *aether.Compressor
	rxCompressor *aether.Compressor

	// streamRefused counts peer-initiated OPEN requests rejected because
	// MaxConcurrentStreams was reached. See _SECURITY.md §3.12.
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

	// OBS-8: per-session delivery-side flow-control telemetry. Cross-
	// adapter parity with NoiseSession.deliveryStats — every
	// DeliverToRecvChWithSignals call on this session points at this
	// shared DeliveryStats so receive-path delivery / drop /
	// backpressure / bytes-dropped counters are session-aggregate.
	// Surfaced through DeliveryStats(); Library MeshMetrics consumes
	// it via AggregateAetherStats to publish aether_deliver_* under
	// /api/monitoring/mesh-debug.
	deliveryStats DeliveryStats
}

// tcpStream is a single Aether stream multiplexed over a TCP connection.
type tcpStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *TCPSession
	state    *aether.StreamStateMachine
	recvCh   chan []byte
	// deliverCh feeds this stream's deliverLoop goroutine. AER-033: the
	// shared readLoop hands each in-order payload here (non-blocking) instead
	// of performing the up-to-1s stream-1 backpressure inline, so a slow
	// consumer on ONE stream can no longer park the readLoop and freeze
	// gossip/keepalive/control/ACK for the whole session. Created in the
	// struct literal (before the stream is visible in s.streams, so the
	// readLoop never races the field); the loop is started post-registration.
	deliverCh        chan []byte
	deliverOnce      sync.Once // closes deliverCh exactly once from teardown
	deliverStartOnce sync.Once // starts deliverLoop exactly once
	// fragBuf reassembles fragmented messages. AER-099: Send fragments a
	// message larger than MaxFrameSize into fragment-headed DATA frames (with
	// [magic|index|total] metadata) so the original message boundary is
	// restored here instead of surfacing each chunk as its own Receive().
	// Touched only by Receive (single-consumer per stream).
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

// closeRecvOnce closes st.recvCh exactly once. Multiple teardown paths
// (handleReset, local Reset, handleClose, streamGC callback) may race
// to release the stream; recvOnce makes the channel-close idempotent so
// none of them panic with `send on closed channel` or `close of closed
// channel`. Any in-flight Receive() returns io.EOF.
func (st *tcpStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
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
	// AER-033: start the per-stream delivery goroutine. deliverCh was created
	// in the struct literal before the stream became visible in s.streams, so
	// starting the drain here (post-registration) is race-free. Guarded so a
	// second attachGrantDebouncer never spawns a second draining goroutine
	// (two rangers on one channel would double-deliver).
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
// stream itself. Idempotent.
func (st *tcpStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
	// AER-033: stop the delivery goroutine. Closing deliverCh ends
	// deliverLoop's range; deliverOnce keeps concurrent teardown paths
	// idempotent. The nil guard covers streams constructed outside the
	// normal paths (direct unit-test construction) where deliverCh is nil.
	if st.deliverCh != nil {
		st.deliverOnce.Do(func() { close(st.deliverCh) })
	}
}

// deliverLoop is the per-stream delivery goroutine. AER-033: it drains
// deliverCh (fed in-order by the single readLoop) and performs the actual
// send into recvCh — including the up-to-1s stream-1 backpressure — OFF the
// readLoop, so a slow application consumer blocks only this goroutine, never
// the shared readLoop / control path. Exits when teardown closes deliverCh.
func (st *tcpStream) deliverLoop() {
	s := st.session
	defer func() {
		// recvCh may be closed by closeRecvOnce (teardown race); recover so a
		// send-on-closed is a benign drop, matching deliverToStream's guard.
		if r := recover(); r != nil {
			dbgTCP.Printf("deliverLoop: send-on-closed for stream %d (race with teardown): %v", st.streamID, r)
		}
	}()
	for payload := range st.deliverCh {
		// The drop accounting (credit grant, congestion signal) lives inside
		// DeliverToRecvChWithSignals' timeout path, so the bool is advisory.
		DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion, &s.deliveryStats)
	}
}

// enqueueDelivery hands one in-order payload to deliverLoop. AER-033:
// non-blocking — the readLoop must never block here. Returns false only when
// deliverCh is full (deliverCh AND recvCh saturated == genuine sustained
// overload); the payload is then dropped with the SAME accounting
// DeliverToRecvChWithSignals' drop path uses (backpressure+dropped stats,
// stream-window grant, CONGESTION signal) so the sender is throttled and never
// stalls on lost credit.
//
// deliverCh is nil only for streams built by direct construction outside the
// normal open paths (unit tests); those fall back to inline delivery so the
// contract still holds, just without the HOL isolation.
func (st *tcpStream) enqueueDelivery(payload []byte) bool {
	s := st.session
	if st.deliverCh == nil {
		return DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion, &s.deliveryStats)
	}
	select {
	case st.deliverCh <- payload:
		return true
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
		txCompressor:  aether.NewCompressor(), // AE-P-05: encode-side state
		rxCompressor:  aether.NewCompressor(), // AE-P-05: decode-side state
		tickStop:      make(chan struct{}),
	}
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
	// implementation in the root aether package. NonBlockingDrop
	// matches pre-consolidation semantics: when the FIFO is full the
	// OPEN-frame handler drops silently rather than stalling readLoop.
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
		// st.Reset deletes from s.streams, closes recvCh, releaseStream.
		_ = st.Reset(aether.ResetTimeout)
	})
	go s.streamGC.Start()

	// Clear any deadline the transport left armed on the conn during its
	// dial/handshake phase. Two known leak sources, both landing here:
	//   - WebSocket dial: gobwas/ws applies the dial context's deadline
	//     to the socket for the handshake and never clears it; the mesh
	//     wraps every dial in a 5 s context, so the socket carries a hard
	//     dialStart+5s read deadline into the session.
	//   - WebSocket/TLS accept: a hijacked HTTP connection keeps whatever
	//     Read/Idle timeout the serving http.Server armed on it.
	// A TCPSession is long-lived and owns its liveness via the keepalive
	// stream + housekeepingTick idle eviction — readLoop blocks
	// indefinitely by design. A leftover deadline fires mid-session and
	// kills it at exactly the dial-timeout mark (observed: grade-C WS
	// sessions dying fleet-wide at lived≈5.00s). Cleared once here, at the
	// single chokepoint every stream transport (WebSocket, TLS) funnels
	// through, so no transport can leak a deadline into a live session.
	_ = conn.SetDeadline(time.Time{})

	go s.readLoop()
	go s.writeLoop()
	go s.housekeepingTick()
	return s
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
	for {
		frame, _, batch, err := aether.ReadNextFrame(s.conn, s.rxCompressor) // AE-P-05: RX state
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
				// AE-M-17: batched sub-frames are decoded by the
				// short-header decoders (codec_short.go), which skip
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
	// AER-033: hand the payload to the per-stream deliverLoop (non-blocking)
	// rather than performing the up-to-1s backpressure inline on the shared
	// readLoop. A slow consumer on this stream then blocks only its own
	// deliverLoop; the readLoop keeps servicing gossip/keepalive/control/ACK
	// for every other stream. enqueueDelivery only sends into a buffered
	// channel here, so the send-on-closed race window (recvCh closed by a
	// concurrent handleClose) moved into deliverLoop, which recovers there.
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
		dbgTCP.Printf("deliverToStream: DROPPED frame for stream %d (%d bytes, deliverCh full)", frame.StreamID, len(frame.Payload))
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
// concurrent peer OPENs cannot race past the cap.
// See _SECURITY.md §3.12 / S5.
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
		session:   s,
		state:     aether.NewStreamStateMachine(),
		recvCh:    make(chan []byte, recvChCapacity(frame.StreamID)),
		deliverCh: make(chan []byte, recvChCapacity(frame.StreamID)),
		fragBuf:   NewFragmentBuffer(),
		window:    flow.NewStreamWindowWithCap(0, 0),
		observe:   reliability.NewObserveEngine(),
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
		streamID:  frame.StreamID,
		config:    cfg,
		session:   s,
		state:     aether.NewStreamStateMachine(),
		recvCh:    make(chan []byte, recvChCapacity(frame.StreamID)),
		deliverCh: make(chan []byte, recvChCapacity(frame.StreamID)),
		fragBuf:   NewFragmentBuffer(),
		window:    flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:   reliability.NewObserveEngine(),
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
		s.txCompressor.RemoveStream(frame.StreamID) // AE-P-05
		s.rxCompressor.RemoveStream(frame.StreamID) // AE-P-05
		return
	}
	// Transition AND remove-from-map BEFORE releasing s.mu, so that any
	// concurrent deliverToStream which has not yet acquired s.mu will
	// see the deleted entry and drop the frame; the residual race (a
	// reader that already cached `st` before this lock acquisition) is
	// handled by deliverToStream's panic-recover.
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
	s.txCompressor.RemoveStream(frame.StreamID) // AE-P-05
	s.rxCompressor.RemoveStream(frame.StreamID) // AE-P-05
}

func (s *TCPSession) handleReset(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if ok {
		delete(s.streams, frame.StreamID)
	}
	s.mu.Unlock()
	s.txCompressor.RemoveStream(frame.StreamID) // AE-P-05
	s.rxCompressor.RemoveStream(frame.StreamID) // AE-P-05
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
// ticker rather than blocking on Consume — pre-refactor parity.
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

// DeliveryStats exposes the session's receive-path delivery counters
// (OBS-8). Cross-adapter parity with NoiseSession.DeliveryStats. The
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
		// frame snapshot burst to drain. Observed effect on v0.0.379:
		// deliver_backpressure==deliver_dropped grew 1:1 at ~1.5/sec
		// due to this exact HoL pattern; skipping stream-0 batching
		// converts the shared writeMu into per-frame fairness without
		// requiring the per-class writeLoop split that F8's larger
		// refactor would entail.
		if s.opts.HeaderComp && frame.StreamID != 0 && s.sched.Len() > 0 {
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
				_, err := s.txCompressor.EncodeBatch(s.conn, batch) // AE-P-05: TX state
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
// Uses v2 short header compression when enabled by kill switch.
func (s *TCPSession) writeFrame(frame *aether.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.opts.HeaderComp {
		// AE-P-05: all encode goes through the TX-side compressor state.
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

	// Full 50-byte header (fallback)
	_, err := aether.EncodeFrame(s.conn, frame)
	if err == nil {
		s.txCompressor.RecordFullHeader(frame) // AE-P-05: TX state
	}
	return err
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface implementation
// ────────────────────────────────────────────────────────────────────────────

func (s *TCPSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		return nil, fmt.Errorf("session closed")
	default:
	}

	st := &tcpStream{
		streamID:  cfg.StreamID,
		config:    cfg,
		session:   s,
		state:     aether.NewStreamStateMachine(),
		recvCh:    make(chan []byte, recvChCapacity(cfg.StreamID)),
		deliverCh: make(chan []byte, recvChCapacity(cfg.StreamID)),
		fragBuf:   NewFragmentBuffer(),
		window:    flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:   reliability.NewObserveEngine(),
	}
	st.state.Transition(aether.EventSendOpen)

	// Locally-initiated open. registerStream(false) enforces the
	// MaxConcurrentStreams cap but skips the peer-side RESET. Surface
	// the typed sentinel ErrStreamCapExhausted so pool/dispatch
	// callers can detect cap-hit via errors.Is and back off rather
	// than closing the session.
	// AE-L-01: registerStream has a tri-state return — nil on cap-hit, the
	// PRE-EXISTING stream when cfg.StreamID is still live in s.streams
	// (duplicate), or st on a fresh insert. Testing only `== nil` let a
	// duplicate fall through and proceed with the detached, never-mapped
	// st: the rollback defer below would delete the live map entry,
	// RegisterWithClass would overwrite its scheduler slot, and inbound
	// DATA would route to the original stream while the returned
	// st.recvCh hangs forever. Compare identity and error out — matching
	// handleOpen's `st != candidate` guard — BEFORE the rollback defer is
	// armed so no cleanup touches the pre-existing stream.
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
	// installed. Repeated probes against a dying peer used to grow s.streams
	// unboundedly because a writeFrame failure returned (nil, err) but left
	// the map entry + GC + scheduler slot + grantDebouncer goroutine pinned.
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

// AcceptStream delegates to the shared aether.StreamAcceptor — the
// adapter no longer owns the FIFO channel + per-transport select. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *TCPSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	dbgTCP.Printf("AcceptStream: waiting...")
	st, err := s.acceptor.Accept(ctx)
	if err == nil {
		if ts, ok := st.(*tcpStream); ok {
			dbgTCP.Printf("AcceptStream: got stream=%d", ts.streamID)
		}
	}
	return st, err
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so the Noise, TCP, and QUIC adapters share one
// implementation rather than each maintaining its own copy.
func (s *TCPSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	return s.acceptor.AcceptByID(ctx, streamID)
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
	// Capture the caller chain so the FIRST closer in a close
	// cascade is identifiable. Frame 0 is this closure, 1 is
	// CloseWithError; frames 2-5 are the actual callers — readLoop
	// defer, stall detector, idle watchdog, the ORBTR dedup/multipath
	// layer, or transport accept-full.
	callerChain := aether.CaptureCallerChain(2, 4)
	// Log EVERY close, including clean nil closes. Previously a
	// nil-error Close() — exactly what the ORBTR dedup/multipath
	// layer calls on a losing session — was silent, so the real
	// churn initiator never appeared in [SESSION-CLOSE] and a
	// downstream readLoop-exit close masked it on the peer. The
	// callers= chain names whoever actually triggered the close.
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
	// Aether-level credit limits on TCP/WS adapters. AER-087: use the
	// non-blocking TryConsume for metrics tracking — the blocking Consume could
	// stall this Send for the full ConsumeTimeout (~10s) on a drained window,
	// contradicting the "TCP native backpressure only" intent. The send
	// proceeds regardless of the return.
	_ = st.window.TryConsume(int64(len(data)))

	// MaxFrameSize enforcement (Task 15): split large payloads into
	// MaxFrameSize-sized chunks so they interleave with other streams
	// via the scheduler, avoiding head-of-line blocking.
	maxFrame := st.session.classDefaults.MaxFrameSize
	if maxFrame <= 0 {
		maxFrame = 65536 // ClassSTREAM default
	}

	totalLen := len(data)

	// AER-099: fragment WITH explicit header/reassembly metadata rather than
	// chopping the message into unrelated DATA frames. The old loop split a
	// payload > maxFrame into headerless chunks with no grouping, so a
	// message-oriented peer saw the boundary silently change (its Receive()
	// returned a truncated head followed by extra messages). SplitPayload tags
	// each chunk [magic|index|total] so the receiver's FragmentBuffer restores
	// the original message; the chunks are still separate DATA frames, so the
	// scheduler interleaving that motivated chunking is preserved. It returns
	// nil for a payload that fits one frame (fast path, no header overhead)
	// except when the payload starts with the fragment magic, which it escapes
	// as a single fragment so IsFragment stays authoritative (AER-068).
	fragments, err := SplitPayload(data, maxFrame)
	if err != nil {
		// Payload exceeds the 255-fragment ceiling at this frame size — fail
		// loudly rather than ship a silently-truncated message (AE-H-03).
		return fmt.Errorf("stream %d: %w", st.streamID, err)
	}
	if fragments == nil {
		fragments = [][]byte{data} // fits one frame — send verbatim
	}
	for _, chunk := range fragments {
		frame := &aether.Frame{
			SenderID:   st.session.LocalPeerID(),
			ReceiverID: st.session.RemotePeerID(),
			StreamID:   st.streamID,
			Type:       aether.TypeDATA,
			Length:     uint32(len(chunk)),
			Payload:    chunk,
		}
		st.session.sched.Enqueue(st.streamID, frame)
	}

	if st.streamID == 0 {
		dbgTCP.Printf("Send: enqueued %d bytes for stream 0 (gossip), schedLen=%d", totalLen, st.session.sched.QueueLen(0))
	}
	return nil
}

func (st *tcpStream) Receive(ctx context.Context) ([]byte, error) {
	for {
		select {
		case data, ok := <-st.recvCh:
			if !ok {
				return nil, io.EOF
			}
			// Consume-driven grant: record the app-consumed bytes in the
			// stream-level debouncer so WINDOW_UPDATE emission advances with
			// application progress, not frame-receipt. Recorded on the raw
			// bytes pulled off recvCh (including any fragment header) so the
			// sender's window advances per fragment, not only on the final
			// reassembly — otherwise a multi-fragment message would stall the
			// sender for the whole reassembly span.
			if st.grantDebouncer != nil {
				st.grantDebouncer.Record(int64(len(data)))
			}
			// AER-099: reassemble fragmented messages so the original message
			// boundary the Send side split is restored, instead of returning
			// each chunk as its own Receive() result.
			if IsFragment(data) {
				if st.fragBuf == nil {
					st.fragBuf = NewFragmentBuffer() // direct-construction fallback
				}
				// recvCh doesn't carry the frame SeqNo, so pass 0 — the
				// per-stream FragmentBuffer uses its own monotonic counter for
				// group keys, and TCP's in-order delivery keeps fragments
				// contiguous within their group.
				assembled, err := st.fragBuf.Add(st.streamID, 0, data)
				if err != nil {
					continue // corrupted/over-cap fragment — skip
				}
				if assembled == nil {
					continue // more fragments needed — loop back to recvCh
				}
				return assembled, nil
			}
			return data, nil
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
	// AE-P-07: free the per-stream compressor entry on local teardown. The
	// compressor keeps per-stream SeqNo state in a separate unbounded sync.Map
	// (codec_short.go Compressor.streams) that only the peer-driven handleClose
	// / handleReset paths prune. Reset is the funnel for every LOCAL teardown —
	// a direct Reset, the streamGC idle-reap callback, and the cancel path all
	// route here — so without this the entry leaks for the session lifetime on
	// locally-reset or GC-reaped streams. Ordering mirrors handleReset:
	// delete-from-streams, then RemoveStream. Post AE-P-05 the compressor is
	// split TX/RX, so free the stream from BOTH directional instances.
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
var _ aether.Stream = (*tcpStream)(nil)

// Suppress unused import warnings for packages used in struct fields.
var _ = (*congestion.Controller)(nil)
