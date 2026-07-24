/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
	"github.com/ORBTR/aether/metrics"
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

	// AE-P-25: removed packetReplay *reliability.PacketReplayWindow — it was
	// an allocated-but-never-read field for a redundant+incorrect third
	// replay layer. Replay is enforced by noise/nonce_window.go (pre-decrypt)
	// and per-stream reliability.ReplayWindow (engine.go Replay.Check).

	// streamRefused counts every stream open rejected because the
	// MaxConcurrentStreams cap is reached — both peer-initiated OPENs
	// (and implicit-OPENs piggy-backed on the first DATA frame) AND
	// locally-initiated OpenStream calls. Operators reading this
	// counter should NOT treat a rising value as exclusively-
	// adversarial peer behaviour — a leak in the local caller (e.g.
	// StreamPool not releasing streams fast enough) also bumps the
	// counter.
	streamRefused uint64

	// writeLoop wake telemetry — pair these two to diagnose missed
	// wakes during cwnd backoff:
	//   cansendFalseReenqueues — incremented every time the writeLoop's
	//     CUBIC.CanSend check fails and the frame is re-enqueued.
	//   wakeOnAckCalls — incremented every time handleACK wakes the
	//     scheduler (every ACK, unconditionally).
	// Surfaced through Metrics(); ConnectionManager.AggregateAetherStats
	// sums them fleet-wide for /api/monitoring/mesh-debug.
	cansendFalseReenqueues uint64
	wakeOnAckCalls         uint64

	// OBS-8: per-session delivery-side flow-control telemetry. Every
	// DeliverToRecvChWithSignals call on this session points at this
	// shared DeliveryStats so receive-path delivery / drop /
	// backpressure / bytes-dropped counters are session-aggregate.
	// Lock-free atomics inside DeliveryStats let the readLoop (single
	// writer per counter per call) and monitoring goroutines
	// (AggregateAetherStats → DeliveryStats() accessor) coexist
	// without synchronisation. Library MeshMetrics consumes it to
	// surface aether_deliver_* under /api/monitoring/mesh-debug.
	deliveryStats DeliveryStats

	// A4 (_SECURITY.md §3.x): per-ACK-interval upper bound for the
	// peer's CEBytes claim. Each outbound payload byte (writeFrame)
	// adds to this counter; each inbound CompositeACK carrying an
	// ECN-piggyback drains it via atomic.Swap and uses the drained
	// value as the maximum-plausible CE claim for that interval.
	// Without this cap a bad-faith peer can advertise CEBytes far
	// larger than anything they could have actually received from us,
	// driving our congestion controller into spurious cwnd collapses
	// (handleACK's per-ACK ackedBytes cap doesn't help when the peer
	// spreads inflated claims across pure-dup ACKs where ackedBytes=0).
	// Overruns are clamped to the drained budget and flagged through
	// reportAbuse(ReasonACKValidation) so the S7 abuse scorer can
	// take action against a repeat offender. Reset semantics: we
	// drain on every CE-bearing ACK, so the "interval" is the time
	// between consecutive CE-bearing ACKs — short and self-clocked.
	bytesSentSinceLastCE atomic.Uint64

	// tlpFiresTotal counts every TLP probe fire (RFC 8985 §7.4). See
	// reliabilityTick's TLP block. Paired with rackMarksTotal — together
	// they describe how loss recovery is splitting between fast-recovery
	// (RACK marks) and tail-recovery (TLP probes). High TLP relative to
	// RACK on a stream that should be sending steadily usually means the
	// sender's ack-clocking is starved (no follow-up data after the last
	// in-flight frame), pointing at app-level send-pacing rather than a
	// loss problem.
	tlpFiresTotal uint64

	// rackMarksTotal counts every seq RACK declares lost (RFC 8985 §6.2).
	// Each call to reliabilityTick's MarkLost loop bumps this by len(lost).
	// Elevated relative to FramesSent indicates either a genuinely lossy
	// path or aggressive RACK reorder-window sizing.
	rackMarksTotal uint64

	// tlpResetTotal counts every time the session-level STALL-DETECT
	// false-positive recovery path runs — i.e. the stall detector
	// declared "no progress" but the probe-before-close Ping
	// succeeded and we reset per-stream TLP exhaustion counters.
	// Bumped once per STALL-DETECT false-positive event in
	// reliabilityTick. Surfaced through SessionMetrics.TLPResetTotal;
	// the connection manager owning the multipath.Manager polls the
	// delta and forwards each event into Manager.RecordTLPReset to
	// drive the PathFlapping demote tier. See multipath/manager.go
	// for the demote semantics.
	tlpResetTotal uint64

	// retransmitEvicted counts frames dropped from a stream's retransmit
	// queue (byte-cap eviction, deadline, or max-retries) — each is a
	// reliable frame that lost its RTO safety net. AER-066.
	retransmitEvicted uint64

	// Observability histograms (see metrics/duration_hist.go). All four
	// histograms are populated on writeLoop / writeFrame hot paths;
	// PercentileSnapshot is read once per Metrics() call (which is a
	// monitoring-cadence operation, not a per-frame one).
	//
	//   writeSyscallHist    — OBS-1: time spent inside the conn.Write call
	//                         (kernel send path / TLS encode / WS write).
	//   writeloopParkHist   — OBS-2: time the writeLoop blocked parked on
	//                         its wake channel.
	//   cwndBlockHist       — OBS-4: duration that CUBIC's CanSend stayed
	//                         false on consecutive writeLoop iterations
	//                         (block-entry to next successful CanSend).
	//   grantStarveHist     — OBS-5: time flow.StreamWindow.Consume blocked
	//                         on the credit semaphore. Shared by every
	//                         stream on the session via SetGrantStarveHist.
	//   cwndUtilRing        — OBS-10: per-mille (inFlight/cwnd) samples
	//                         captured every cwndUtilSamplePeriod writes.
	//   recvWindowHOLHist   — OBS-13: recv-window head-of-line-block latency.
	//                         Time between a frame's buffer arrival and its
	//                         ordered delivery to the application. Shared
	//                         across all streams on the session (same pattern
	//                         as grantStarveHist) via SetHOLHist at
	//                         createStream time.
	//   streamSendBlockHist — OBS-14: caller-block latency inside noiseStream.Send.
	//                         Wall-clock time the application spent inside the
	//                         Send call (window.Consume + connWindow.Consume +
	//                         sendSingleFrame) from entry to return. Distinct
	//                         from writeloopParkHist (OBS-2), which measures
	//                         the writeLoop's internal park on its wake
	//                         channel — that's the sender-side scheduler view;
	//                         this is the application-facing view of "how long
	//                         did my Send block". Shared across all streams
	//                         on the session via the streamSendBlockHist ptr
	//                         field on noiseStream (set at createStream).
	//                         Samples below streamSendBlockFloor are skipped
	//                         and counted in streamSendFastTotal instead — the
	//                         same fast-path skip pattern as OBS-5's
	//                         grantStarveHist.
	writeSyscallHist    metrics.DurationHist
	writeloopParkHist   metrics.DurationHist
	cwndBlockHist       metrics.DurationHist
	grantStarveHist     metrics.DurationHist
	cwndUtilRing        metrics.PermilleRing
	recvWindowHOLHist   metrics.DurationHist
	streamSendBlockHist metrics.DurationHist
	// OBS-14b: per-phase decomposition of streamSendBlockHist. Recorded
	// at each phase boundary inside noiseStream.Send so operators can
	// attribute application-facing send latency to per-stream credit
	// starvation vs per-conn credit starvation vs the post-credit
	// encrypt/write/park path. Same fast-path skip as streamSendBlockHist
	// applies — phase durations below streamSendBlockFloor are not
	// recorded so the fast path doesn't dominate.
	perStreamWindowWaitHist metrics.DurationHist
	connWindowWaitHist      metrics.DurationHist
	postCreditSendHist      metrics.DurationHist
	// schedulerDepthRing — OBS-9: scheduler queue-depth distribution.
	// Wired into s.sched via SetDepthHist at session construction so
	// every Enqueue / EnqueueProbe / external Wake and every writeLoop
	// pre-park ObserveDepth() pushes the current queue depth into the
	// ring. PercentileSnapshot is read once per Metrics() call.
	schedulerDepthRing metrics.Uint32Ring

	// streamSendFastTotal counts the number of noiseStream.Send calls that
	// completed faster than streamSendBlockFloor. These calls bypass the
	// streamSendBlockHist Record — recording every microsecond-fast send
	// would dominate the distribution with uncontended noise and bury the
	// real caller-block signal we want OBS-14 to surface. The fast-total
	// counter preserves the "how many sends were uncontended" signal that
	// would otherwise be lost. Same pattern as OBS-5's fast-path skip in
	// flow.StreamWindow.Consume.
	streamSendFastTotal atomic.Uint64

	// cwndUtilCounter sequences writes so we sample cwnd-util every
	// cwndUtilSamplePeriod-th send. Atomic so the writeLoop (single
	// goroutine today, but future multi-writer designs would race on a
	// plain uint64). Wrap is harmless — we only inspect counter % period.
	cwndUtilCounter uint64

	// inFlightBytes aggregates the on-wire size of every unacked frame
	// across every stream's SendWindow. Each stream's SendWindow is
	// wired into this counter via SetSessionInFlightCounter at
	// createStream time, so SendWindow.Add / .Ack paths
	// increment/decrement it as a side effect. writeLoop's CUBIC
	// CanSend check reads via a single atomic.Load instead of walking
	// every stream's window under per-stream locks.
	//
	// Consistency: each mutation is sequenced under the per-stream
	// SendWindow.mu, so the counter never under-reports relative to the
	// per-stream entries-map content.
	inFlightBytes atomic.Int64

	// Session-aggregate frame and byte counters consumed by Metrics().
	// bytesSent/framesSent are bumped in writeFrame (counts every send
	// attempt — see writeFrame for the at-attempt-vs-at-success
	// rationale). bytesRecv/framesRecv are bumped at dispatchFrame on
	// the receive path. Payload-byte semantics (matches
	// aether.SessionMetrics.BytesSent / BytesRecv), not on-wire bytes
	// including frame headers.
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	framesSent atomic.Uint64
	framesRecv atomic.Uint64

	// appBytesDelivered counts payload bytes actually DELIVERED to an
	// application DATA stream (handleData / TypeDATA), NOT dispatch-path
	// bytesRecv (which counts every frame incl. control/gossip/ACK). This
	// is the un-gameable "this is a real, delivering mesh member" signal
	// used by reportAbuse's T2 grade-A discriminator (AER-074 extension):
	// a peer flooding malformed frames / bad ACKs never reaches app
	// delivery (malformed fails Validate; bad-ACK hits TypeACK not
	// handleData), so it can never shelter into the forensic-only tier.
	// See reportAbuse. (R-839/M-99: LastActivity + bytesRecv both refresh
	// PRE-Validate and are gameable; app-delivery is not.)
	appBytesDelivered atomic.Uint64

	// forensicSuppressed counts guard-covered abuse events (ack-validation /
	// malformed-frame) that were RECORDED for observability but deliberately
	// NOT scored/closed because the session is established + grade-A (past
	// warmup + actively app-delivering). Surfaced so triage can still see a
	// genuine post-warmup attack that (A) intentionally stops closing —
	// keeps R-838 "everything still scored" real without arming the
	// blacklist (which would relocate the reap to a reconnect-lockout).
	forensicSuppressed atomic.Uint64

	// lastPeerStats stores the most-recent STATS frame the peer emitted.
	// Updated by handleStats (every ~5s per the peer's reliabilityTick).
	// Read-only consumers (monitoring, Library MeshMetrics) call
	// LastPeerStats() to get a snapshot. atomic.Pointer for lock-free
	// readers; nil until the peer's first STATS frame arrives.
	lastPeerStats atomic.Pointer[aether.SessionMetrics]

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

	// Short header compression, per-stream state. AER-048: separate encode
	// (tx) and decode (rx) compressors. A single shared instance let the
	// peer's inbound sequence numbers and the local outbound sequence numbers
	// cross-contaminate the same StreamCompState.lastSeqNo and
	// SessionCompState.lastSender/lastReceiver, corrupting short-header deltas
	// and identity stamping on bidirectional streams. The TCP adapter fixed
	// this same class as AE-P-05.
	txCompressor *aether.Compressor
	rxCompressor *aether.Compressor

	// Per-frame encryption (optional — Noise already encrypts the transport layer)
	// Set via SetSessionKey when per-frame AEAD is needed (e.g., relay scenarios)
	encryptor  *aethercrypto.FrameEncryptor
	sessionKey []byte

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

	// prevAnyInFlight records whether the previous reliabilityTick observed
	// any in-flight data. When in-flight transitions 0→N (a fresh burst
	// after an idle gap) the stall detector reseeds lastAnyProgressAt so a
	// request/response workload that idled past SessionStallThreshold isn't
	// declared stuck the instant it sends again — before any ACK could
	// possibly return. Guarded by s.mu.
	prevAnyInFlight bool

	// peerMaxAckDelay is the peer's advertised max_ack_delay (RFC 9002
	// §6.2) extracted from the Noise handshake NodeInfo payload via the
	// optional noiseConnAckDelay interface on conn. Used by createStream
	// to seed each new noiseStream's TLP.SetMaxAckDelay with the peer's
	// actually-advertised value — replacing the previous receiver-side
	// approximation max(ACKPolicy.MaxDelay, SRTT/4) which we used while
	// the handshake didn't carry the value. Zero means the peer didn't
	// advertise (e.g. an over-conn substrate that uses the minimal
	// NodeInfo encoding) — createStream falls back to the receiver-side
	// approximation in that case. Read lock-free since the field is
	// frozen at construction.
	peerMaxAckDelay time.Duration
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
		BaseSession: base,
		conn:        conn,
		layout:      aether.DefaultStreamLayout(),
		opts:        opts,
		streams:     make(map[uint64]*noiseStream),
		sched:       scheduler.NewScheduler(),
		connWindow:  flow.NewConnWindow(0),
		pacer:       selectPacer(opts),
		// connGrantDebouncer initialized below after s is assigned, because
		// the grantable + sendUpdate bindings reference s itself.
		fecEncoder:         reliability.NewFECEncoder(reliability.DefaultFECGroupSize),
		fecDecoder:         reliability.NewFECDecoder(),
		interleavedEncoder: reliability.NewInterleavedFECEncoder(reliability.DefaultFECGroupSize),
		interleavedDecoder: reliability.NewInterleavedFECDecoder(),
		txCompressor:       aether.NewCompressor(),
		rxCompressor:       aether.NewCompressor(),
	}
	// Reed-Solomon encoder/decoder — instantiated even when no stream is
	// using FECReedSolomon, because the cost is just a small Galois-field
	// table. Streams opt in via StreamConfig.FECLevel = FECReedSolomon.
	s.rsEncoder, _ = reliability.NewRSEncoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)
	s.rsDecoder, _ = reliability.NewRSDecoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)

	// Lift the peer's advertised max_ack_delay off the underlying
	// noiseConn (when the substrate supports the handshake-capability
	// surface). createStream uses this to seed each stream's TLP PTO
	// per RFC 9002 §6.2 instead of the receiver-side approximation.
	// A nil / minimal substrate (e.g. over-conn handshake without the
	// extended NodeInfo) leaves the field zero and createStream falls
	// back to max(ACKPolicy.MaxDelay, SRTT/4).
	if pmad, ok := conn.(noiseConnAckDelay); ok {
		s.peerMaxAckDelay = pmad.PeerMaxAckDelay()
	}

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

	// OBS-9: wire the scheduler-depth histogram so every Enqueue /
	// EnqueueProbe / Wake samples the current queue depth and every
	// writeLoop pre-park ObserveDepth() captures the drained-empty
	// tail of the distribution. Must happen before the writeLoop and
	// any RPC traffic so the first signal is recorded.
	s.sched.SetDepthHist(&s.schedulerDepthRing)

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
	// AE-P-25: removed s.packetReplay allocation — PacketReplayWindow was a
	// redundant+incorrect third replay layer (see noise_dispatch.go). Replay
	// is enforced by noise/nonce_window.go (pre-decrypt) and per-stream
	// reliability.ReplayWindow (engine.go Replay.Check).
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

	// Locally-initiated open. enforceRemoteCap=false means: enforce
	// the MaxConcurrentStreams cap but do NOT send a RESET back (no
	// peer to RESET — the caller gets the error directly). The cap
	// applies universally so a leaking local caller can't exhaust the
	// session's stream-slot table.
	st := s.createStream(cfg.StreamID, cfg, false)
	if st == nil {
		// Cap reached. streamRefused counter already incremented inside
		// createStream; abuse signal recorded. Surface the typed
		// sentinel ErrStreamCapExhausted so callers can detect cap-hit
		// via errors.Is and back off instead of closing the session.
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = aether.DefaultMaxConcurrentStreams
		}
		return nil, fmt.Errorf("OpenStream cap=%d: %w", cap, aether.ErrStreamCapExhausted)
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
	// CloseSignal() is owned by BaseSession and IS allocated; the local
	// `s.closed` field (declared on NoiseSession but never make()d) was
	// silently passing nil here, which kept the WaitForActivityPing
	// closeSignal select-arm always-blocked and defeated the documented
	// fast-fail-on-dead-session behaviour. Use the BaseSession signal
	// so a session torn down mid-probe returns ErrSessionClosed
	// immediately instead of polling LastActivity for the deadline.
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
	dropped, probe := s.sched.Unregister(streamID)
	// AER-078: release the connection-window credit reserved by frames that
	// were queued in the scheduler but never reached the wire (the stream was
	// torn down with frames still queued). Scheduler.Unregister already returns
	// them; ignoring the return stranded HeaderSize+Length conn credit per
	// frame, draining the 4MB window under stream churn until Send failed with
	// "insufficient connection credit". Only metered bytes were reserved (small
	// frames bypass Consume). The per-stream window is discarded with the
	// stream, and the conn window has its own lock, so this is safe from the GC
	// sweep path that must not re-acquire s.mu.
	relConn := func(f *aether.Frame) {
		if f != nil && int64(f.Length) > flow.MinGuaranteedWindow {
			s.connWindow.ReleaseUnsent(int64(f.Length))
		}
	}
	for _, f := range dropped {
		relConn(f)
	}
	relConn(probe)
	if s.streamGC != nil {
		s.streamGC.Unregister(streamID)
	}
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
	// why the watchdog thought the session was stuck. Read under s.mu:
	// lastAnyProgressAt is a multi-word time.Time written under the lock
	// during reliabilityTick, so an unsynchronised read here is a race.
	s.mu.Lock()
	lastProgress := s.lastAnyProgressAt
	s.mu.Unlock()
	stallSince := "n/a"
	if !lastProgress.IsZero() {
		stallSince = fmt.Sprintf("%v", time.Since(lastProgress))
	}
	lifetime := time.Since(s.CreatedAt())
	warmupGrace := s.opts.SessionWarmupGrace
	if warmupGrace == 0 {
		warmupGrace = aether.DefaultSessionWarmupGrace
	}
	warmupActive := warmupGrace > 0 && lifetime < warmupGrace
	log.Printf("[SESSION-CLOSE] noise peer=%s lifetime=%v warmup=%v err=%v stalled=%s callers=%s",
		remoteShort, lifetime, warmupActive, err, stallSince, callerChain)
	if err != nil {
		s.SetCloseErr(err)
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
		id           uint64
		inFlight     int
		sendBase     uint32
		sendNext     uint32
		recvExp      uint32
		recvBuffered int
		recvDrops    uint64
		flowStats    flow.Stats
		srtt         time.Duration
		progressAge  time.Duration
		rack         congestion.State
		tlp          congestion.TLPState
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
	sessionAge := now.Sub(s.CreatedAt())

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
	// AE-P-02: reject a second install so a key is never silently re-installed
	// into a fresh FrameEncryptor whose ordered nonce counter restarts at 0.
	// The encryptor's per-instance random nonce prefix already makes reinstall
	// nonce-safe, but a re-key mid-session is a caller bug (both directions
	// share the single s.encryptor); fail loud instead of masking it.
	if s.encryptor != nil {
		return fmt.Errorf("aether: session key already set")
	}
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
// `inboxDrops`, rekey counters (OBS-15), and ECN CE-byte observations
// can flow through to SessionMetrics without the adapter needing a
// direct import of the noise/ package.
type noiseConnStats interface {
	DecryptErrors() uint64
	InboxDrops() uint64
	// OBS-15 rekey telemetry: lifetime rekey count + bytes encrypted
	// since the last rekey. Pass-through to the embedded RekeyTracker
	// on the noiseConn (noise/rekey.go). Older noiseConn types that
	// haven't grown these methods miss the type assertion and the
	// counters stay zero — graceful degradation by design.
	RekeyTotal() uint64
	RekeyBytesSinceLast() uint64
	// OBS-18 AEAD-decrypt latency distribution: p50/p99 of the per-call
	// recv-side decrypt cost in microseconds. Sourced from the
	// noiseConn's decryptLatencyHist ring buffer (noise/session.go).
	// Bimodal p50/p99 split = CPU-saturated host queuing decrypt
	// goroutines; both tiers in µs = healthy. Zero when no samples yet.
	DecryptLatencySnapshot() (p50Us, p99Us uint64)
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

// noiseConnAckDelay is the optional handshake-capability surface exposed
// by *noiseConn — the noise/ handshake completion path captures the
// peer's advertised max_ack_delay (RFC 9002 §6.2) from the NodeInfo
// payload onto the noiseConn before NewNoiseSession ever sees the conn,
// and the constructor probes via this interface to lift the value onto
// the session. Kept separate from noiseConnStats because tests can
// compose substitute net.Conn implementations that don't need to satisfy
// the full stats surface to exercise stream open paths. A nil / unknown
// implementation produces a zero result, which createStream interprets
// as "peer didn't advertise — fall back to the receiver-side
// approximation".
type noiseConnAckDelay interface {
	PeerMaxAckDelay() time.Duration
}

func (s *NoiseSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	var suspiciousACKs, recvDrops, seqWraps, replayDup, replayAncient uint64
	// rttSrc is the stream we read percentile RTT from for the
	// session-level snapshot. Pick the FIRST stream whose RTT estimator
	// is initialised — any data-carrying stream produces samples on
	// every ACK (noise_dispatch.go::handleACK → st.rtt.UpdateWithDelay).
	//
	// Do NOT prefer s.layout.Control: that's the key-rotation / STATS
	// stream and by design carries no application TypeDATA, so its rtt
	// estimator never initialises. An unconditional controlID-first
	// assignment would clobber every data stream's estimator and the
	// session-level RTT would be 0 even when streams 0 (gossip) and 1
	// (RPC) have fresh samples.
	var rttSrc *reliability.RTTEstimator
	for _, st := range s.streams {
		if st.sendWindow != nil {
			suspiciousACKs += st.sendWindow.SuspiciousACKsCount()
		}
		if st.recvWindow != nil {
			recvDrops += st.recvWindow.DropsCount()
		}
		if st.replay != nil {
			seqWraps += st.replay.WrapsDetectedCount()
			replayDup += st.replay.DuplicateCount()
			replayAncient += st.replay.AncientDropCount()
		}
		if rttSrc == nil && st.rtt != nil && st.rtt.IsInitialized() {
			rttSrc = st.rtt
		}
	}
	s.mu.Unlock()

	var rttP50, rttP95, rttP99 time.Duration
	if rttSrc != nil {
		rttP50, rttP95, rttP99 = rttSrc.PercentileSnapshot()
	}

	// Transport-level counters from the underlying *noiseConn. The same
	// type-assertion gates all four pass-throughs: when the conn is a
	// non-noise net.Conn (e.g. test loopback) every counter is zero,
	// which matches the documented "noise-only" semantics on the
	// SessionMetrics RekeyTotal / RekeyBytesSinceLast fields.
	var decryptErr, inboxDrops, rekeyTotal, rekeyBytesSinceLast uint64
	var decryptLatencyP50Us, decryptLatencyP99Us uint64
	if stats, ok := s.conn.(noiseConnStats); ok {
		decryptErr = stats.DecryptErrors()
		inboxDrops = stats.InboxDrops()
		rekeyTotal = stats.RekeyTotal()
		rekeyBytesSinceLast = stats.RekeyBytesSinceLast()
		decryptLatencyP50Us, decryptLatencyP99Us = stats.DecryptLatencySnapshot()
	}

	// FEC eviction total must include all three decoders — XOR, interleaved,
	// and Reed-Solomon — otherwise operators under-count when RS is in use.
	fecEvicted := s.fecDecoder.EvictedCount() + s.interleavedDecoder.EvictedCount()
	if s.rsDecoder != nil {
		fecEvicted += s.rsDecoder.EvictedCount()
	}

	// ACK-emit triggers — global counters across all engines on this
	// process (not per-session). Reveal which ACK path dominates when
	// summed fleet-wide: high delay-timer counts on sub-RTT paths point
	// at the adaptive delayed-ACK floor as the latency source.
	ackImmediate, ackDelayTimer, ackDup := reliability.AckEmitStats()

	// Observability histogram percentile readouts. Computed once per
	// Metrics() call (a monitoring-cadence operation, not a hot path).
	// Each PercentileSnapshot acquires its histogram's mutex briefly to
	// copy the ring then sorts the copy — cost is a few µs each.
	writeSyscallP50, _, writeSyscallP99 := s.writeSyscallHist.PercentileSnapshot()
	parkP50, _, parkP99 := s.writeloopParkHist.PercentileSnapshot()
	cwndBlockP50, _, cwndBlockP99 := s.cwndBlockHist.PercentileSnapshot()
	grantStarveP50, _, grantStarveP99 := s.grantStarveHist.PercentileSnapshot()
	cwndUtilP50, cwndUtilP99 := s.cwndUtilRing.PercentileSnapshot()
	holP50, _, holP99 := s.recvWindowHOLHist.PercentileSnapshot()
	streamSendBlockP50, _, streamSendBlockP99 := s.streamSendBlockHist.PercentileSnapshot()
	perStreamWaitP50, _, perStreamWaitP99 := s.perStreamWindowWaitHist.PercentileSnapshot()
	connWaitP50, _, connWaitP99 := s.connWindowWaitHist.PercentileSnapshot()
	postCreditP50, _, postCreditP99 := s.postCreditSendHist.PercentileSnapshot()
	schedulerDepthP50, schedulerDepthP99 := s.schedulerDepthRing.PercentileSnapshot()

	return aether.SessionMetrics{
		RTT:                avg,
		CWND:               s.congestion().CWND(),
		ActiveStreams:      streamCount,
		SuspiciousACKs:     suspiciousACKs,
		ForensicSuppressed: s.forensicSuppressed.Load(),
		FECGroupsEvicted:   fecEvicted,
		StreamRefused:      s.StreamRefusedCount(),
		SeqNoWraps:         seqWraps,
		RecvWindowDrops:    recvDrops,
		DecryptErrors:      decryptErr,
		InboxDrops:         inboxDrops,
		// Anti-replay classification (Classify/Commit split). ReplayRejects
		// preserved as the sum so old consumers reading the aggregate
		// see the same total — the split surfaces the operational
		// meaning. See SessionMetrics docs for the distinction.
		ReplayDuplicates: replayDup,
		ReplayAncient:    replayAncient,
		ReplayRejects:    replayDup + replayAncient + seqWraps,

		CanSendFalseReenqueues: atomic.LoadUint64(&s.cansendFalseReenqueues),
		WakeOnAckCalls:         atomic.LoadUint64(&s.wakeOnAckCalls),
		AckEmitDelayTimer:      ackDelayTimer,
		AckEmitImmediate:       ackImmediate,
		AckEmitDuplicate:       ackDup,

		// Per-session frame and byte totals. See the bytesSent /
		// bytesRecv / framesSent / framesRecv field doc on
		// NoiseSession for payload-byte semantics. FramesRecv pairs
		// with FramesSent to compute the per-session send/recv frame
		// ratio and is one of the asymmetric-loss inputs the STATS
		// codec ships to the peer's quality scorer.
		BytesSent:  s.bytesSent.Load(),
		BytesRecv:  s.bytesRecv.Load(),
		FramesSent: s.framesSent.Load(),
		FramesRecv: s.framesRecv.Load(),

		RttP50: rttP50,
		RttP95: rttP95,
		RttP99: rttP99,

		// Health-monitor SRTT — populated by Pong arrivals via the
		// WaitForActivityPing → hm.RecordPingSent → hm.RecordPongRecv
		// chain. Independent of the per-stream RTT estimator
		// (RttP50/95/99) which only updates on DATA-frame ACKs; on a
		// session with no application traffic the per-stream values
		// stay 0 while HealthSRTT still reflects ping-derived liveness.
		HealthSRTTUs: uint64(s.Health().SRTT().Microseconds()),

		// Observability histograms (OBS-1/2/4/5/10) and counters
		// (OBS-11). Percentile readouts are computed above; the int64
		// microsecond values from DurationHist are cast to uint64 here
		// to match the SessionMetrics field type. Negative values are
		// impossible (Record drops d <= 0) so the cast is lossless.
		WriteSyscallP50Us:   uint64(writeSyscallP50),
		WriteSyscallP99Us:   uint64(writeSyscallP99),
		WriteloopParkP50Us:  uint64(parkP50),
		WriteloopParkP99Us:  uint64(parkP99),
		CubicCwndBlockP50Us: uint64(cwndBlockP50),
		CubicCwndBlockP99Us: uint64(cwndBlockP99),
		GrantStarveP50Us:    uint64(grantStarveP50),
		GrantStarveP99Us:    uint64(grantStarveP99),
		CwndUtilP50Permille: cwndUtilP50,
		CwndUtilP99Permille: cwndUtilP99,
		TLPFiresTotal:       atomic.LoadUint64(&s.tlpFiresTotal),
		RACKMarksTotal:      atomic.LoadUint64(&s.rackMarksTotal),
		TLPResetTotal:       atomic.LoadUint64(&s.tlpResetTotal),

		// OBS-15: surface noise send-cipher rekey telemetry. Sourced
		// from the RekeyTracker on the underlying *noiseConn via the
		// noiseConnStats interface probe above.
		RekeyTotal:          rekeyTotal,
		RekeyBytesSinceLast: rekeyBytesSinceLast,

		// OBS-18: per-decrypt AEAD latency distribution. Sourced from
		// the decryptLatencyHist on the underlying *noiseConn via the
		// same noiseConnStats interface probe. Captures the bimodal
		// uncontended-vs-CPU-queued split that ordinary RTT histograms
		// hide. Zero on non-noise adapters (test loopback etc.).
		DecryptLatencyP50Us: decryptLatencyP50Us,
		DecryptLatencyP99Us: decryptLatencyP99Us,

		// OBS-13: recv-window HOL-block percentiles. Populated by every
		// stream's RecvWindow when frames are flushed after waiting for
		// predecessors. Zero when no reordering has occurred this session.
		RecvWindowHOLP50Us: uint64(holP50),
		RecvWindowHOLP99Us: uint64(holP99),

		// OBS-14: caller-block percentiles for Stream.Send. Populated by
		// noiseStream.Send via a defer that records (Send-return − Send-
		// entry). Distinct from WriteloopParkP*Us: this is the application-
		// facing block, that is the writeLoop's internal park. Samples
		// below streamSendBlockFloor (50µs) bypass the histogram and are
		// counted in StreamSendFastTotal so operators see both the tail
		// and the uncontended denominator.
		StreamSendBlockP50Us: uint64(streamSendBlockP50),
		StreamSendBlockP99Us: uint64(streamSendBlockP99),
		StreamSendFastTotal:  s.streamSendFastTotal.Load(),

		// OBS-14b: per-phase decomposition of StreamSendBlock. Recorded
		// at each phase boundary inside noiseStream.Send so operators
		// can attribute application-facing send latency to (a) per-stream
		// credit starvation, (b) per-conn credit starvation, or (c) the
		// post-credit encrypt+write+park path. Sum approximation:
		// StreamSendBlock ≈ PerStreamWindowWait + ConnWindowWait + PostCreditSend.
		PerStreamWindowWaitP50Us: uint64(perStreamWaitP50),
		PerStreamWindowWaitP99Us: uint64(perStreamWaitP99),
		ConnWindowWaitP50Us:      uint64(connWaitP50),
		ConnWindowWaitP99Us:      uint64(connWaitP99),
		PostCreditSendP50Us:      uint64(postCreditP50),
		PostCreditSendP99Us:      uint64(postCreditP99),

		// OBS-9: scheduler queue-depth percentiles. Sampled on every
		// signalWake (Enqueue / EnqueueProbe / external Wake) and on
		// every writeLoop pre-park ObserveDepth() call inside
		// noise_reliability.go's writeLoop, so the distribution
		// covers both the "work arrives" face (instantaneous depth
		// post-Enqueue) and the "drained-empty" tail (depth just
		// before the writeLoop parks on WakeCh). Zero on transports
		// that don't wire a depth ring into their scheduler.
		SchedulerDepthP50: schedulerDepthP50,
		SchedulerDepthP99: schedulerDepthP99,
	}
}

// StreamRefusedCount returns the number of peer-initiated stream opens
// rejected because MaxConcurrentStreams was reached.
func (s *NoiseSession) StreamRefusedCount() uint64 {
	return atomic.LoadUint64(&s.streamRefused)
}

// LastPeerStats returns a copy of the most-recent STATS frame received
// from the peer, or a zero-value SessionMetrics if no STATS frame has
// arrived yet. Lock-free read via atomic.Pointer. Periodic STATS
// emission from the peer is driven by reliabilityTick → handleSTATS in
// noise_dispatch.go.
func (s *NoiseSession) LastPeerStats() aether.SessionMetrics {
	if p := s.lastPeerStats.Load(); p != nil {
		return *p
	}
	return aether.SessionMetrics{}
}

// reportAbuse records a misbehaviour event against the remote peer.
// Delegates to the shared AbuseTracker, which handles the registry
// Record + threshold-breaker GoAway + close. See aether/abuse_tracker.go
// for the shape.
//
// AER-074: the three ack-validation guards (BaseACK-jump / oversize-range /
// invalid-bitmap in ProcessCompositeACK, and the A4 CE-overclaim clamp) trip as
// FALSE POSITIVES during the session warmup window: the send-window base is
// still settling and CE plausibility (Outstanding()) is small because the
// window is still filling, so a well-behaved peer's early ACKs read as
// suspicious. At weight 25 / threshold 100, four such trips inside the 60s
// warmup grace GOAWAY-close a healthy same-org UDP session before it ever
// stabilises (observed fleet-wide: [SESSION-CLOSE] ... lifetime=~58s
// warmup=true reason: ack-validation — the noise-UDP churn that keeps the
// session count collapsing to 0-1). Suppress ONLY ReasonACKValidation during
// warmup: the guard has already rejected/clamped the offending ACK (the
// CPU-exhaustion protection is in the guard, not in the score), so scoring it
// here only kills legitimate sessions. Every other reason (decrypt-fail,
// malformed-frame, replay, protocol-violation, flow-control) is an attack
// regardless of lifetime and still enforces immediately. A genuine crafted-ACK
// attacker is bounded to the warmup window (its ACKs are still rejected) and
// scores + closes the instant warmup ends.
//
// AER-074 EXTENSION (R-837/R-839/M-98 — the ~110s fleet churn): the guard
// covers BOTH ack-validation AND malformed-frame, and the false-positive is
// NOT confined to warmup — a legit established session's recovery ACKs / large
// frames also trip the guard post-warmup and GOAWAY-close a healthy grade-A
// session. Since the guard already dropped/clamped the frame (CPU protection
// is in the guard, not the score), scoring→closing is redundant + kills legit
// sessions. Three tiers for the two guard-covered reasons:
//   T1 warmup (< SessionWarmupGrace): SUPPRESS (no score) — original AER-074.
//   T2 established grade-A (past warmup + actively app-DELIVERING,
//      appBytesDelivered>0): FORENSIC-ONLY — record (forensicSuppressed) for
//      triage visibility but do NOT score / close / arm the blacklist. A
//      flooder never delivers app data (malformed fails Validate; bad-ACK is
//      TypeACK, not handleData) so it can never reach T2. NOT blacklist-arming
//      is deliberate (R-839): arming would relocate the reap-cycle to a
//      reconnect-LOCKOUT — strictly worse.
//   T3 post-warmup zombie (past warmup + never app-delivered): FULL Report —
//      a genuine slow-loris that only ever sends garbage still scores + closes
//      + is blacklisted at the accept gate.
// Every OTHER reason (decrypt-fail / replay / protocol-violation /
// flow-control-abuse — none cheap-guard-neutralized) enforces in every tier.
func (s *NoiseSession) reportAbuse(r abuse.Reason) {
	if r == abuse.ReasonACKValidation || r == abuse.ReasonMalformedFrame {
		warmupGrace := s.opts.SessionWarmupGrace
		if warmupGrace == 0 {
			warmupGrace = aether.DefaultSessionWarmupGrace
		}
		if warmupGrace > 0 && time.Since(s.CreatedAt()) < warmupGrace {
			return // T1: warmup-sync artifact, not abuse
		}
		if s.appBytesDelivered.Load() > 0 {
			// T2: established, grade-A (real delivering peer). The offending
			// frame is already dropped by the guard; record for observability
			// but do NOT enforce — no score, no close, no blacklist-arm.
			s.forensicSuppressed.Add(1)
			return
		}
		// T3: past warmup + never delivered app data → a genuine slow-loris.
		// Fall through to full Report (score + close + accept-gate blacklist).
	}
	s.abuseTracker.Report(r)
}

// ForensicSuppressedCount returns the number of guard-covered abuse events
// (ack-validation / malformed-frame) that were RECORDED but deliberately not
// scored/closed on this established grade-A session (AER-074 T2). Surfaced via
// MeshMetrics so triage retains visibility into a genuine post-warmup attack
// that the forensic-only tier intentionally stops closing.
func (s *NoiseSession) ForensicSuppressedCount() uint64 {
	return s.forensicSuppressed.Load()
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
