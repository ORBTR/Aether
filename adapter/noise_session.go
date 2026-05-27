//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	aethercrypto "github.com/ORBTR/aether/crypto"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/migration"
	"github.com/ORBTR/aether/pmtu"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// NoiseSession implements Session over a Noise-encrypted UDP connection.
// This is the MOST COMPLEX adapter — Noise provides only encryption and identity.
// Everything else is provided by Aether:
//   - Frame codec (encode/decode Aether frames)
//   - Stream multiplexing (StreamID → per-stream state)
//   - Reliability (SACK, retransmission, reorder buffer per stream)
//   - Flow control (credit-based WINDOW_UPDATE per stream + connection)
//   - Congestion control (CUBIC per connection)
//   - FEC (XOR repair per stream)
//   - Priority scheduling (WFQ)
//   - Anti-replay (sliding window per stream)
type NoiseSession struct {
	// BaseSession owns the identity + lifecycle + accessor surface
	// (LocalNodeID/RemoteNodeID/LocalPeerID/RemotePeerID/ConnectionID/
	// Capabilities/Protocol/Health/IsClosed/LastActivity/IdleTimeout)
	// shared with the TCP + QUIC adapters. Embedded as a pointer so
	// the close-signal channel + sync.Once are safe across the read /
	// write / reliability / ticker goroutines.
	*aether.BaseSession

	mu   sync.Mutex
	conn net.Conn // the Noise-encrypted connection (reads/writes encrypted UDP datagrams)

	// Stream management
	streams map[uint64]*noiseStream

	// acceptor owns per-StreamID accept dispatch — pinned waiters,
	// per-ID backlog, and the FIFO that AcceptStream drains. Lives in
	// the root aether package so all three transport adapters (Noise,
	// TCP, QUIC) share one implementation rather than each carrying
	// their own channel + push-mode shim. handleOpen /
	// handleImplicitOpen call acceptor.Notify on every accepted
	// stream; AcceptStream and AcceptStreamByID delegate to it.
	acceptor *aether.StreamAcceptor

	// Stream layout — consumer-defined stream ID assignments
	layout aether.StreamLayout
	opts   aether.SessionOptions

	// Shared infrastructure
	writeMu    sync.Mutex
	healthMon  *health.Monitor
	sched      *scheduler.Scheduler
	connWindow *flow.ConnWindow
	// connGrantDebouncer coalesces conn-level WINDOW_UPDATE emissions
	// driven by application reads across ALL streams on this session.
	// When stream.Receive() records consumed bytes, both the per-stream
	// debouncer AND this session-wide debouncer fire in parallel; the
	// conn-level one emits a single StreamConnectionLevel grant per
	// coalesce window no matter how many streams are actively reading.
	connGrantDebouncer *grantDebouncer
	// cong is the active congestion controller. Stored behind an
	// atomic.Pointer so SetCongestionController can swap it safely
	// while handleACK / writeLoop / reliabilityTick concurrently read.
	// Use s.congestion() / s.setCongestion() — never touch directly.
	cong  atomic.Pointer[congestion.Controller]
	pacer congestion.PacingPolicy

	// FEC (shared encoder/decoder). Three modes co-exist on the session
	// because each stream independently chooses its FECLevel:
	//   FECBasicXOR    → fecEncoder       / fecDecoder
	//   FECInterleaved → interleavedEnc/Dec
	//   FECReedSolomon → rsEncoder        / rsDecoder
	fecEncoder         *reliability.FECEncoder
	fecDecoder         *reliability.FECDecoder
	interleavedEncoder *reliability.InterleavedFECEncoder
	interleavedDecoder *reliability.InterleavedFECDecoder
	rsEncoder          *reliability.RSEncoder
	rsDecoder          *reliability.RSDecoder

	// PMTU discovery (UDP only)
	pmtuProber *pmtu.Prober

	// Connection migration handler
	migrator *migration.Migrator

	// Packet-level anti-replay (connection-scoped, 128-bit window)
	packetReplay *reliability.PacketReplayWindow

	// streamRefused counts peer-initiated OPEN / implicit-OPEN requests
	// rejected because the MaxConcurrentStreams cap is reached.
	streamRefused uint64

	// ECN observation. The receive path increments ceObservedBytes
	// when an inbound packet's IP/IPv6 TOS field carries the CE codepoint
	// (0x03). The next outbound CompositeACK reads-and-resets this counter
	// into its CEBytes extension so the sender can call cong.OnCE.
	// Socket-level cmsg plumbing (IP_RECVTOS / IPV6_RECVTCLASS) lives in
	// the noise/ package; this counter is the protocol-level handoff.
	ceObservedBytes uint64

	// Runtime-mutable compression toggle. Initialised from
	// opts.Compression at construction, flipped at runtime via
	// SetCompressionEnabled (aether.CompressionCapable interface).
	// writeFrame reads this atomic rather than s.opts.Compression so
	// link-change handlers (e.g. agent netmon detecting cellular ↔
	// wifi transitions) can flip compression without reconstructing
	// the session. The adaptive CPU controller also flips it under
	// high load.
	compressionEnabled atomic.Bool

	// Peer abuse scoring (_SECURITY.md §3.6/§3.9/§3.12). The shared
	// AbuseTracker owns the registry, the threshold-breaker GoAway,
	// and the threshold-breaker session close. Defaults to a
	// per-session registry (1 entry); SetAbuseScoreRegistry replaces
	// it with a shared one so cross-session dashboards can see a
	// peer's behaviour across every connection in one place.
	// `reportAbuse` forwards every misbehaviour-counter site into
	// this tracker.
	abuseTracker *aether.AbuseTracker

	// Stream GC — resets idle streams after timeout (exempts well-known 0-3)
	streamGC *aether.StreamGC

	// Stall-detection state moved onto noiseStream as atomic fields — see
	// lastBaseACKSeen / lastProgressAtUnixNano on noiseStream. Colocation
	// ties the tracker lifetime to the stream (no leak on close) and
	// removes the unsynchronised map write that lived here before.

	// FEC prune scheduling — rate-limit decoder GC to ~1/sec.
	// Without pruning, FECDecoder.groups grows unbounded under adversarial
	// FEC_REPAIR flooding with unique GroupIDs. See _SECURITY.md §3.5.
	lastFECPrune time.Time

	// Connection identity and transport class
	connID        aether.ConnectionID
	classDefaults aether.TransportClassDefaults

	// Short header compression (v2 — per-stream state)
	compressor *aether.Compressor

	// Per-frame encryption (optional — Noise already encrypts the transport layer)
	// Set via SetSessionKey when per-frame AEAD is needed (e.g., relay scenarios)
	encryptor  *aethercrypto.FrameEncryptor
	sessionKey []byte

	// Tick management
	tickStop  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	// throttle holds the explicit-CONGESTION signal state from the peer.
	// Zero value is "no throttle"; handleCongestion updates it on incoming
	// CONGESTION frames. Send-path consumers can consult Throttle() for
	// RateFactor/ShouldStall before committing large sends.
	throttle aether.CongestionThrottle

	// lastAutoTune is the wall-clock time of the last flow-control auto-tune
	// pass. The reliability tick runs every 10 ms but auto-tune only runs
	// every 10 s — this timestamp rate-limits it inside the tick loop.
	lastAutoTune time.Time

	// lastGrantRefresh is the wall-clock time of the last periodic
	// WINDOW_UPDATE re-emission for all live streams on this session.
	// Breaks the UDP-loss deadlock where a dropped grant stalls the sender
	// and no further data arrives to re-trigger the threshold.
	lastGrantRefresh time.Time

	// lastAnyProgressAt is the wall-clock time that any stream on this
	// session most recently made ACK-progress (i.e. BaseACK advanced).
	// When zero it's seeded to session-start. Consulted by the session-
	// level stall detector: if every in-flight stream sits without
	// progress past SessionStallThreshold the session closes itself with
	// ErrSessionStuck so the owning connection manager can fall back to
	// a lower-grade transport (e.g. Noise-UDP → WS) rather than thrash
	// on a black-holed path. Updated under s.mu during reliabilityTick.
	lastAnyProgressAt time.Time

	// createdAt is the wall-clock time the session was constructed.
	// Used by the stall detector together with opts.SessionWarmupGrace
	// to compute an effective stall threshold that's larger during
	// the session's initial lifetime — see reliabilityTick. Set once
	// in NewNoiseSession and read lock-free thereafter.
	createdAt time.Time
}

// NewNoiseSession creates an Aether session over a Noise-encrypted
// connection. opts controls every session-level feature (FEC,
// compression, encryption, header compression, frame logging,
// congestion algorithm, per-session caps like MaxConcurrentStreams /
// MaxFECGroups / SessionIdleTimeout).
//
// Always takes SessionOptions. Numeric / string zero-values fall back
// to documented defaults via aether.NormalizeSessionOptions. Boolean
// fields are honoured as-supplied — start from
// aether.DefaultSessionOptions() if you want features enabled and only
// want to override specific fields.
func NewNoiseSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *NoiseSession {
	opts = aether.NormalizeSessionOptions(opts)
	base := aether.NewBaseSession(localNodeID, remoteNodeID, aether.ProtoNoise)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	base.SetIdleTimeouts(opts.SessionIdleTimeout, aether.DefaultSessionIdleTimeout)
	s := &NoiseSession{
		BaseSession:        base,
		conn:               conn,
		layout:             aether.DefaultStreamLayout(),
		opts:               opts,
		streams:            make(map[uint64]*noiseStream),
		sched:              scheduler.NewScheduler(),
		connWindow:         flow.NewConnWindow(0),
		pacer:              selectPacer(opts),
		// connGrantDebouncer initialized below after s is assigned, because
		// the grantable + sendUpdate bindings reference s itself.
		fecEncoder:         reliability.NewFECEncoder(reliability.DefaultFECGroupSize),
		fecDecoder:         reliability.NewFECDecoder(),
		interleavedEncoder: reliability.NewInterleavedFECEncoder(reliability.DefaultFECGroupSize),
		interleavedDecoder: reliability.NewInterleavedFECDecoder(),
		compressor:         aether.NewCompressor(),
		tickStop:           make(chan struct{}),
		createdAt:          time.Now(),
	}
	// Reed-Solomon encoder/decoder — instantiated even when no stream is
	// using FECReedSolomon, because the cost is just a small Galois-field
	// table. Streams opt in via StreamConfig.FECLevel = FECReedSolomon.
	s.rsEncoder, _ = reliability.NewRSEncoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)
	s.rsDecoder, _ = reliability.NewRSDecoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)

	// Session-wide conn-level grant debouncer. Immediate-flush floor at
	// 50% of DefaultConnCredit so burst patterns don't wait the full
	// coalesce window when the sender is close to the conn-level edge.
	s.connGrantDebouncer = newGrantDebouncer(
		s.connWindow,
		s.sendWindowUpdateAgnostic,
		aether.StreamConnectionLevel,
		int64(float64(flow.DefaultConnCredit)*GrantImmediateFraction),
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

	// Initial congestion controller — stored atomically so the setter
	// can swap without racing the ACK / write / tick paths.
	initialCong := selectCongestionController(opts)
	s.cong.Store(&initialCong)

	// Compression toggle — seeded from opts.Compression so the initial
	// policy matches what the caller asked for. SetCompressionEnabled
	// can flip this at runtime.
	s.compressionEnabled.Store(opts.Compression)

	// Per-peer abuse scoring (S7). One score registry per session — the
	// remote peer is the only key that matters, so a 1-entry registry is
	// fine. Consumers that want cross-session scoring (e.g. a mesh-level
	// operator dashboard) can replace this via SetAbuseScoreRegistry.
	// The tracker wraps the registry plus the threshold-breaker GoAway +
	// close hooks so reportAbuse stays a one-liner.
	s.abuseTracker = aether.NewAbuseTracker(
		abuse.New[aether.NodeID](abuse.DefaultConfig()),
		remoteNodeID,
		func(reason aether.GoAwayReason, msg string) error {
			return s.GoAway(context.Background(), reason, msg)
		},
		s.CloseWithError,
		dbgNoise.Printf,
	)

	s.migrator = migration.NewMigrator()
	s.packetReplay = reliability.NewPacketReplayWindow()
	// connID is owned by *BaseSession (initialised by NewBaseSession).
	s.classDefaults = aether.DefaultsForClass(aether.ClassRAW)
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(streamID uint64) {
		dbgNoise.Printf("StreamGC: resetting idle stream %d", streamID)
		s.mu.Lock()
		st, ok := s.streams[streamID]
		if ok {
			delete(s.streams, streamID)
		}
		s.mu.Unlock()
		if ok {
			// Send RESET to the peer. st.Reset also calls sched.Unregister,
			// but we then run releaseStream to idempotently clean up every
			// session-side tracker (sched + streamGC). The streamGC sweep
			// itself deletes this stream from its own map right after
			// invoking this callback, so Unregister here is a no-op on
			// that side but harmless.
			_ = st.Reset(aether.ResetTimeout)
		}
		s.releaseStream(streamID)
	})

	// PMTU prober sends PATH_PROBE frames to discover maximum segment size
	s.pmtuProber = pmtu.NewProber(func(probeID uint32, paddingSize uint16) error {
		payload := aether.EncodePathProbe(probeID, paddingSize)
		frame := &aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   s.layout.Control,
			Type:       aether.TypePATH_PROBE,
			Length:     uint32(len(payload)),
			Payload:    payload,
		}
		return s.writeFrame(frame)
	})

	go s.readLoop()
	go s.writeLoop()
	go s.reliabilityTick()
	go s.streamGC.Start()        // idle stream garbage collection
	go s.pmtuProber.StartProbe() // begin PMTU discovery immediately
	return s
}

// congestion returns the live congestion controller. Cheap (single atomic
// load) so call sites don't need to cache. Never returns nil after
// NewNoiseSession completes because the constructor always Stores one.
func (s *NoiseSession) congestion() congestion.Controller {
	if p := s.cong.Load(); p != nil {
		return *p
	}
	return nil
}

// selectCongestionController chooses between CUBIC (default) and BBR.
// Checks opts.CongestionAlgo first, then falls back to AETHER_CONGESTION env var.
func selectCongestionController(opts aether.SessionOptions) congestion.Controller {
	algo := opts.CongestionAlgo
	if algo == "" {
		algo = os.Getenv("AETHER_CONGESTION")
	}
	if algo == "bbr" {
		return congestion.NewBBRController()
	}
	return congestion.NewCUBICController()
}

// selectPacer chooses the right pacing policy for the configured congestion
// algorithm: SendTimePacer for BBR (matches BBR's send-time scheduling
// model), token-bucket Pacer for CUBIC (CUBIC has no pacing model so
// burst-tolerant token-bucket is fine).
func selectPacer(opts aether.SessionOptions) congestion.PacingPolicy {
	algo := opts.CongestionAlgo
	if algo == "" {
		algo = os.Getenv("AETHER_CONGESTION")
	}
	if algo == "bbr" {
		return congestion.NewSendTimePacer(0)
	}
	return congestion.NewPacer(0, 64*1024) // 64KB burst; rate updated by congestion controller
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface
// ────────────────────────────────────────────────────────────────────────────

func (s *NoiseSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		return nil, fmt.Errorf("session closed")
	default:
	}

	// Stream ID exhaustion check
	if cfg.StreamID > aether.MaxStreamID {
		return nil, fmt.Errorf("stream ID %d exceeds MaxStreamID (%d) — send GOAWAY", cfg.StreamID, aether.MaxStreamID)
	}

	// Locally-initiated open: no remote cap enforcement (we control when
	// we open streams).
	st := s.createStream(cfg.StreamID, cfg, false)
	if st == nil {
		// Should never happen with enforceRemoteCap=false, but defend.
		return nil, fmt.Errorf("createStream returned nil")
	}
	st.state.Transition(aether.EventSendOpen)

	// Send OPEN frame
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	})
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   cfg.StreamID,
		Type:       aether.TypeOPEN,
		Length:     uint32(len(openPayload)),
		Payload:    openPayload,
	}
	if err := s.writeFrame(frame); err != nil {
		return nil, err
	}
	return st, nil
}

// AcceptStream delegates to the shared aether.StreamAcceptor — the
// adapter no longer owns the FIFO channel + per-transport select. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *NoiseSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	return s.acceptor.Accept(ctx)
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so all three transport adapters share one
// implementation. Local consumer-pinning semantics are unchanged
// (gossip=0, rpc=1, keepalive=2, control=3, reconcile=4, swarm=100,
// etc. each get exclusive claim regardless of wire arrival order).
func (s *NoiseSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	return s.acceptor.AcceptByID(ctx, streamID)
}

// notifyStreamAccepted hands a freshly-accepted stream to the shared
// StreamAcceptor. The acceptor picks between a pinned ByID waiter, a
// per-ID backlog slot, or the internal FIFO that AcceptStream drains.
// Called by handleOpen / handleImplicitOpen — the two paths that
// produce a remotely-initiated stream.
func (s *NoiseSession) notifyStreamAccepted(st *noiseStream) {
	s.acceptor.Notify(st)
}

// Identity / Capabilities / Protocol accessors are promoted from the
// embedded *BaseSession.

// Ping sends a PING frame and waits briefly for any inbound activity
// (PONG response or any other frame) before reporting the cached RTT.
//
// Pre-v0.0.22 returned the cached health.Monitor RTT immediately after
// writeFrame returned nil, regardless of whether the peer was actually
// reachable. That made keepalive blind to zombie sessions: the session's
// `closed` channel could be closed (IsClosed=true) but s.conn.Write
// queued the frame into a buffered writer that surfaced the network
// error several seconds later — by which time keepalive's per-tick
// retry budget was already spent on stale "OK" responses, and avg RTT
// was the snapshot from the last completed PING/PONG round-trip.
//
// v0.0.22:
//   1. Fast-fail if IsClosed already — avoids syscall for known-dead
//      sessions and lets keepalive distinguish "stuck send" from
//      "session torn down".
//   2. Capture LastActivity before writeFrame, then poll until either
//      ctx fires, IsClosed flips, the activity timestamp advances, or
//      a 2 s ceiling is reached (clamped by ctx deadline if shorter).
//      Any inbound frame counts as "alive" — we deliberately don't
//      track per-PING seqNo to avoid adding state. False positives
//      (peer happens to send something else within 2 s) are fine for
//      the keepalive use case; the goal is detecting silence.
func (s *NoiseSession) Ping(ctx context.Context) (time.Duration, error) {
	return aether.WaitForActivityPing(ctx, s.Health(), s.closed, func(seqNo uint32) error {
		return s.writeFrame(&aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   s.layout.Keepalive,
			Type:       aether.TypePING,
			SeqNo:      seqNo,
		})
	})
}

func (s *NoiseSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	return aether.SendGoAway(s.writeFrame, s.LocalPeerID(), s.RemotePeerID(), s.layout.Control, reason, message)
}

// releaseStream performs the session-side cleanup that every stream
// termination path needs: unregister from the scheduler and from the
// idle-stream GC. Callers must already have removed the stream from
// s.streams under s.mu (and closed recvCh where appropriate) — this
// helper intentionally does neither so it can be called from the GC
// sweep (which cannot re-acquire s.mu) and the RESET/CLOSE handlers
// (which run under different lock disciplines).
//
// All operations are idempotent: calling for a streamID that was
// already unregistered is a no-op on both the scheduler and the GC.
func (s *NoiseSession) releaseStream(streamID uint64) {
	s.sched.Unregister(streamID)
	if s.streamGC != nil {
		s.streamGC.Unregister(streamID)
	}
}

// CloseErr returns the error the session was closed with, or nil if it
// was closed cleanly (or is still open). Safe to call after Close; the
// underlying field is only written inside closeOnce.Do.
func (s *NoiseSession) CloseErr() error {
	return s.closeErr
}

func (s *NoiseSession) Close() error {
	return s.CloseWithError(nil)
}

func (s *NoiseSession) CloseWithError(err error) error {
	if !s.SignalClose() {
		return nil
	}
	// Capture caller chain to find the actual close trigger. Frame 0
	// is this method, frames 1+ are the callers — show 3 levels so we
	// can distinguish keepalive timeout vs stream-stuck vs reliability
	// watchdog vs application Close().
	callerChain := aether.CaptureCallerChain(1, 3)
	remoteShort := string(s.RemoteNodeID())
	if len(remoteShort) > 14 {
		remoteShort = remoteShort[:14] + "..."
	}
	// Snapshot watchdog-relevant state at close time so we can see
	// why the watchdog thought the session was stuck.
	stallSince := "n/a"
	if !s.lastAnyProgressAt.IsZero() {
		stallSince = fmt.Sprintf("%v", time.Since(s.lastAnyProgressAt))
	}
	lifetime := time.Since(s.createdAt)
	warmupGrace := s.opts.SessionWarmupGrace
	if warmupGrace == 0 {
		warmupGrace = aether.DefaultSessionWarmupGrace
	}
	warmupActive := warmupGrace > 0 && lifetime < warmupGrace
	log.Printf("[SESSION-CLOSE] noise peer=%s lifetime=%v warmup=%v err=%v stalled=%s callers=%s",
		remoteShort, lifetime, warmupActive, err, stallSince, callerChain)
	if err != nil {
		s.closeErr = err
	}
	if s.streamGC != nil {
		s.streamGC.Stop()
	}
	// Flush any pending conn-level grant so the peer gets credit for
	// bytes the application did consume, even if the session is
	// tearing down. Idempotent; safe even if never initialized.
	if s.connGrantDebouncer != nil {
		s.connGrantDebouncer.Close()
	}
	// Release any AcceptStreamByID waiters and drain the per-ID
	// backlog so blocked callers return ErrSessionClosed instead of
	// hanging. Backlog streams are reset because their recvCh /
	// reliability engine is otherwise orphaned — the acceptor
	// surfaces them and the adapter calls Reset because the
	// transport-specific teardown lives here.
	if s.acceptor != nil {
		for _, st := range s.acceptor.Close() {
			_ = st.Reset(aether.ResetCancel)
		}
	}
	s.conn.Close()
	return nil
}

// dumpFlowDiagOnStall emits a single high-detail [FLOW-DIAG] line capturing
// the full flow-control + reliability + congestion state at the moment a
// stall event fires. Called from the stall detector for both false-positive
// (rescued by probe) and confirmed-stuck (closing for fallback) branches —
// the diff between rescued and killed dumps is the diagnostic gold here.
//
// Per-stream: inFlight frames, sendBase/next, recvExpected/buffered/drops,
// flow stream-window stats (currentWindow, outstanding, recvCredit,
// consumed, grant-trigger breakdown), srtt, progressAge.
// Session: congestion CWND + pacing rate, conn-window stats, lastAutoTune
// age, lastGrantRefresh age, sessionAge.
//
// Designed to fit on one line per stream + one summary line so a single
// stall event produces a small bounded log burst even on a 50-stream
// session. No lock acquisition beyond the briefest snapshot pass.
func (s *NoiseSession) dumpFlowDiagOnStall(reason string) {
	remoteShort := s.RemoteNodeID().Short()
	now := time.Now()

	type streamRow struct {
		id          uint64
		inFlight    int
		sendBase    uint32
		sendNext    uint32
		recvExp     uint32
		recvBuffered int
		recvDrops   uint64
		flowStats   flow.Stats
		srtt        time.Duration
		progressAge time.Duration
		rack        congestion.State
		tlp         congestion.TLPState
	}

	s.mu.Lock()
	rows := make([]streamRow, 0, len(s.streams))
	for streamID, st := range s.streams {
		row := streamRow{id: streamID}
		if st.sendWindow != nil {
			row.inFlight = st.sendWindow.InFlight()
			row.sendBase = st.sendWindow.Base()
			row.sendNext = st.sendWindow.Next()
		}
		if st.recvWindow != nil {
			row.recvExp = st.recvWindow.ExpectedSeqNo()
			row.recvBuffered = st.recvWindow.BufferedCount()
			row.recvDrops = st.recvWindow.DropsCount()
		}
		if st.window != nil {
			row.flowStats = st.window.Stats()
		}
		if st.rtt != nil {
			row.srtt = st.rtt.SRTT()
		}
		if pn := st.lastProgressAtUnixNano.Load(); pn != 0 {
			row.progressAge = now.Sub(time.Unix(0, pn))
		}
		if st.rack != nil {
			row.rack = st.rack.Snapshot()
		}
		if st.tlp != nil {
			row.tlp = st.tlp.Snapshot()
		}
		rows = append(rows, row)
	}
	autoTuneAge := now.Sub(s.lastAutoTune)
	grantRefreshAge := now.Sub(s.lastGrantRefresh)
	s.mu.Unlock()

	cong := s.congestion()
	var cwnd int64
	var pacing float64
	if cong != nil {
		cwnd = cong.CWND()
		pacing = cong.PacingRate()
	}
	connStats := s.connWindow.Stats()
	sessionAge := now.Sub(s.createdAt)

	log.Printf("[FLOW-DIAG] %s reason=%s sessionAge=%v cwnd=%d pacing=%.0fbps autoTuneAge=%v grantRefreshAge=%v conn{out=%d credit=%d cons=%d gE=%d gR=%d thr=%d eag=%d wm=%d tim=%d} streams=%d",
		remoteShort, reason, sessionAge, cwnd, pacing, autoTuneAge, grantRefreshAge,
		connStats.Outstanding, connStats.RecvCredit, connStats.Consumed,
		connStats.GrantsEmitted, connStats.GrantsReceived,
		connStats.ThresholdGrants, connStats.EagerGrants,
		connStats.WatermarkGrants, connStats.TimedGrants,
		len(rows))
	for _, r := range rows {
		var fackAge time.Duration
		if !r.rack.LastDeliveredAt.IsZero() {
			fackAge = now.Sub(r.rack.LastDeliveredAt)
		}
		var tlpScheduledIn time.Duration
		if !r.tlp.ScheduledAt.IsZero() {
			tlpScheduledIn = r.tlp.ScheduledAt.Sub(now)
		}
		log.Printf("[FLOW-DIAG] %s stream=%d inFlight=%d send{base=%d next=%d} recv{exp=%d buf=%d drops=%d} flow{cur=%d out=%d credit=%d cons=%d thr=%d eag=%d wm=%d tim=%d} srtt=%v progressAge=%v rack{fackSeq=%d fackAge=%v reoWnd=%v marked=%d} tlp{scheduledIn=%v probePending=%v probes=%d pto=%v}",
			remoteShort, r.id, r.inFlight,
			r.sendBase, r.sendNext,
			r.recvExp, r.recvBuffered, r.recvDrops,
			r.flowStats.CurrentWindow, r.flowStats.Outstanding,
			r.flowStats.RecvCredit, r.flowStats.Consumed,
			r.flowStats.ThresholdGrants, r.flowStats.EagerGrants,
			r.flowStats.WatermarkGrants, r.flowStats.TimedGrants,
			r.srtt, r.progressAge,
			r.rack.FackSeq, fackAge, r.rack.ReoWnd, r.rack.MarkedLost,
			tlpScheduledIn, r.tlp.ProbePending, r.tlp.ConsecutiveProbes, r.tlp.PTO)
	}
}

func (s *NoiseSession) MSS() int { return s.pmtuProber.MSS() }

// SetSessionKey sets the per-frame encryption key and enables AEAD encryption.
// The key should be derived from the Noise handshake shared secret.
// When set, all outbound frames are encrypted and inbound frames are decrypted.
func (s *NoiseSession) SetSessionKey(key [32]byte) error {
	enc, err := aethercrypto.NewFrameEncryptor(key, true)
	if err != nil {
		return err
	}
	s.encryptor = enc
	s.sessionKey = key[:]
	return nil
}

// SetCongestionController replaces the congestion controller (CUBIC or BBR).
// Safe to call at any time — the swap is atomic. The pacer rate is
// automatically updated from the new controller's PacingRate() after each
// ACK. In-flight OnAck / OnLoss calls on the old controller complete
// normally; subsequent reads observe the new one.
func (s *NoiseSession) SetCongestionController(cc congestion.Controller) {
	s.cong.Store(&cc)
}
// ConnectionID / Health / Protocol all come from the embedded *BaseSession.

func (s *NoiseSession) SessionKey() []byte      { return s.sessionKey }
func (s *NoiseSession) CongestionWindow() int64 { return s.congestion().CWND() }
// noiseConnStats is the optional observability surface exposed by the
// underlying *noiseConn. We probe via interface so `decryptErrors`,
// `inboxDrops`, and ECN CE-byte observations can flow through to
// SessionMetrics without the adapter needing a direct import of the
// noise/ package.
type noiseConnStats interface {
	DecryptErrors() uint64
	InboxDrops() uint64
}

// noiseConnCE is the optional ECN hook exposed by *noiseConn — the
// listener's ecnReader fills a CE-byte counter on the conn whenever a
// CE-marked datagram is received (#15), and the adapter drains that
// counter on every outbound CompositeACK so the sender's OnCE handler
// reacts one RTT before queue overflow. Kept separate from
// noiseConnStats because ECN support is best-effort (not all kernels /
// build tags enable it) and the adapter has its own ceObservedBytes
// fallback for test scenarios that write directly via RecordCEBytes.
type noiseConnCE interface {
	DrainCEBytes() uint64
}

func (s *NoiseSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	var suspiciousACKs, recvDrops, seqWraps uint64
	for _, st := range s.streams {
		if st.sendWindow != nil {
			suspiciousACKs += st.sendWindow.SuspiciousACKsCount()
		}
		if st.recvWindow != nil {
			recvDrops += st.recvWindow.DropsCount()
		}
		if st.replay != nil {
			seqWraps += st.replay.WrapsDetectedCount()
		}
	}
	s.mu.Unlock()

	// Transport-level counters from the underlying *noiseConn.
	var decryptErr, inboxDrops uint64
	if stats, ok := s.conn.(noiseConnStats); ok {
		decryptErr = stats.DecryptErrors()
		inboxDrops = stats.InboxDrops()
	}

	// FEC eviction total must include all three decoders — XOR, interleaved,
	// and Reed-Solomon — otherwise operators under-count when RS is in use.
	fecEvicted := s.fecDecoder.EvictedCount() + s.interleavedDecoder.EvictedCount()
	if s.rsDecoder != nil {
		fecEvicted += s.rsDecoder.EvictedCount()
	}

	return aether.SessionMetrics{
		RTT:              avg,
		CWND:             s.congestion().CWND(),
		ActiveStreams:    streamCount,
		SuspiciousACKs:   suspiciousACKs,
		FECGroupsEvicted: fecEvicted,
		StreamRefused:    s.StreamRefusedCount(),
		SeqNoWraps:       seqWraps,
		RecvWindowDrops:  recvDrops,
		DecryptErrors:    decryptErr,
		InboxDrops:       inboxDrops,
	}
}

// StreamRefusedCount returns the number of peer-initiated stream opens
// rejected because MaxConcurrentStreams was reached.
func (s *NoiseSession) StreamRefusedCount() uint64 {
	return atomic.LoadUint64(&s.streamRefused)
}

// reportAbuse records a misbehaviour event against the remote peer.
// Delegates to the shared AbuseTracker, which handles the registry
// Record + threshold-breaker GoAway + close. See aether/abuse_tracker.go
// for the shape.
func (s *NoiseSession) reportAbuse(r abuse.Reason) {
	s.abuseTracker.Report(r)
}

// PeerAbuseScore returns the remote peer's current score (exponentially
// decayed since last update). Useful for observability dashboards.
func (s *NoiseSession) PeerAbuseScore() float64 {
	score, _ := s.abuseTracker.PeerScore()
	return score
}

// SetAbuseScoreRegistry replaces the per-session abuse registry with a
// shared one. Consumers that want cross-session scoring (e.g. a mesh-level
// operator dashboard that tracks a peer's misbehaviour across every
// connection) pass in a single `abuse.Score[aether.NodeID]` shared among
// all NoiseSessions pointed at that peer. Must be called before the
// session sees live traffic — the field is read by reportAbuse on every
// bad-behaviour event, and swapping it under traffic would lose the in-
// flight event about to Record().
//
// Signature takes `interface{}` to satisfy `aether.AbuseScoreCapable`
// (which can't import abuse/ to avoid a cycle). Returns false when the
// argument is not `*abuse.Score[aether.NodeID]` — the concrete type the
// tracker expects.
func (s *NoiseSession) SetAbuseScoreRegistry(r interface{}) bool {
	return s.abuseTracker.SetRegistry(r)
}

// LastActivity / IdleTimeout / IsClosed are all promoted from the
// embedded *BaseSession (BaseSession holds the override + default).

// CompressionEnabled returns the current runtime compression toggle.
// Starts from opts.Compression at construction; can be flipped at
// runtime via SetCompressionEnabled.
func (s *NoiseSession) CompressionEnabled() bool {
	return s.compressionEnabled.Load()
}

// SetCompressionEnabled flips the runtime compression toggle. Safe
// to call under live traffic — the atomic swap is picked up on the
// next frame encode. Typical callers: agent netmon detecting a
// link-type change (cellular ↔ wifi), adaptive CPU controller under
// sustained load, or an operator-driven override.
func (s *NoiseSession) SetCompressionEnabled(enabled bool) {
	s.compressionEnabled.Store(enabled)
}

// maxStreamSRTT returns the largest SRTT across all live streams (or 0 if
// none has a sample yet). Used by the FEC age-pruner to pick a TTL of
// 2×SRTT — anything older than that would have been superseded by
// retransmission anyway.
func (s *NoiseSession) maxStreamSRTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max time.Duration
	for _, st := range s.streams {
		if st.rtt == nil {
			continue
		}
		if srtt := st.rtt.SRTT(); srtt > max {
			max = srtt
		}
	}
	return max
}

// refreshWindowGrants re-emits the current cumulative WINDOW_UPDATE for
// every live stream plus the connection-level window. Called from
// reliabilityTick at 2s cadence.
//
// The cumulative-grant design (see flow.StreamWindow docs) makes duplicate
// grants harmless — the peer's ApplyUpdate drops any incoming credit
// that's ≤ what's already been applied. So re-emitting the same value is
// always safe, and it recovers from UDP packet loss without needing any
// ACK / retry logic.
//
// Skips streams where no grant has ever been emitted (CurrentGrant == 0)
// since re-emitting 0 is pointless and would noise the wire.
func (s *NoiseSession) refreshWindowGrants() {
	s.mu.Lock()
	streams := make([]*noiseStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()

	for _, st := range streams {
		if cg := st.window.CurrentGrant(); cg > 0 {
			s.sendWindowUpdate(st.streamID, uint64(cg))
		}
	}
	if cg := s.connWindow.CurrentGrant(); cg > 0 {
		s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(cg))
	}
}

// autoTuneWindows feeds per-stream RTT into each stream's flow window and
// applies a bounded grow/shrink based on SuggestedWindow. Called from
// reliabilityTick at 10s cadence. Disabled when AETHER_AUTOTUNE=off.
// Uses per-stream reliability-engine SRTT (more accurate than session RTT
// for Noise); falls back to healthMon RTT if the stream has no samples yet.
func (s *NoiseSession) autoTuneWindows() {
	if aether.AutoTuneDisabled() {
		return
	}
	_, sessionAvgRTT := s.Health().RTT()

	s.mu.Lock()
	streams := make([]*noiseStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()

	for _, st := range streams {
		// Prefer per-stream SRTT when available — reliability engine observes
		// ACK timing which is more precise than keepalive PING/PONG.
		rtt := st.rtt.SRTT()
		if rtt <= 0 {
			rtt = sessionAvgRTT
		}
		res := aether.AutoTuneWindow(st.window, rtt)
		switch res.Action {
		case "grow":
			if res.Applied > 0 {
				dbgNoise.Printf("autoTune stream=%d grow=%d current=%d rtt=%s",
					st.streamID, res.Applied, res.Current, rtt)
			}
		case "shrink":
			if res.Applied > 0 {
				dbgNoise.Printf("autoTune stream=%d shrink=%d current=%d rtt=%s",
					st.streamID, res.Applied, res.Current, rtt)
			}
		}
	}
}

// Compile-time interface check
var _ aether.Session = (*NoiseSession)(nil)
var _ aether.AbuseScoreCapable = (*NoiseSession)(nil)
var _ aether.IdleEvictable = (*NoiseSession)(nil)
var _ aether.CompressionCapable = (*NoiseSession)(nil)
