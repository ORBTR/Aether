/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"net"
	"time"

	"github.com/ORBTR/aether/health"
)

// Session represents a multiplexed connection to a peer using the Aether wire protocol.
// Every transport adapter implements this interface, mapping Aether semantics to native capabilities.
type Session interface {
	// OpenStream creates a new stream with the given configuration.
	// The stream is ready for Send/Receive after OpenStream returns.
	OpenStream(ctx context.Context, cfg StreamConfig) (Stream, error)

	// AcceptStream waits for a remotely-opened stream (OPEN frame from peer).
	// Returns the stream with the configuration the peer requested.
	// FIFO: returns whatever stream arrives next on the wire — appropriate
	// for dynamic-stream consumers (e.g. RPC server accepting unpredictable
	// stream IDs ≥ 10). Consumers that need a specific well-known stream
	// (gossip=0, rpc=1, keepalive=2, control=3, reconcile=4, swarm=100,
	// etc.) should use AcceptStreamByID to avoid mis-routing when streams
	// arrive out-of-order on the wire.
	AcceptStream(ctx context.Context) (Stream, error)

	// AcceptStreamByID blocks until a stream with exactly the requested
	// StreamID arrives, regardless of the order streams hit the wire. The
	// well-known mesh streams (gossip=0, rpc=1, keepalive=2, control=3,
	// reconcile=4) and any other ID-pinned consumers (e.g. swarm=100)
	// should use this rather than AcceptStream so an out-of-order OPEN
	// for a different ID doesn't get mis-claimed by the wrong consumer.
	//
	// Streams whose IDs are not currently awaited by a ByID waiter are
	// either parked on a small per-ID backlog (drained by the next
	// matching AcceptStreamByID call) or, when no backlog slot is
	// available, fall through to the FIFO acceptCh so dynamic-stream
	// consumers calling AcceptStream still see them.
	//
	// On session close, all blocked AcceptStreamByID callers return
	// ErrSessionClosed.
	AcceptStreamByID(ctx context.Context, streamID uint64) (Stream, error)

	// LocalNodeID returns this node's full identity.
	LocalNodeID() NodeID

	// RemoteNodeID returns the peer's full identity.
	RemoteNodeID() NodeID

	// LocalPeerID returns the truncated 8-byte identity for frame headers.
	LocalPeerID() PeerID

	// RemotePeerID returns the peer's truncated 8-byte identity.
	RemotePeerID() PeerID

	// Capabilities returns what this transport natively provides.
	// Adapters use this to skip redundant Aether layers (e.g., QUIC skips reliability).
	Capabilities() Capabilities

	// Ping sends a PING frame and returns the round-trip time.
	Ping(ctx context.Context) (time.Duration, error)

	// GoAway initiates graceful shutdown with a reason code and optional message.
	// After GoAway, no new streams can be opened. Existing streams drain.
	GoAway(ctx context.Context, reason GoAwayReason, message string) error

	// Close tears down the session and all streams immediately.
	Close() error

	// IsClosed returns true if the session has been closed.
	IsClosed() bool

	// Health returns the session health monitor for RTT, missed pings, activity tracking.
	Health() *health.Monitor

	// SessionKey returns the shared secret for Aether-level frame encryption.
	// Returns nil if the transport provides native encryption (ENCRYPTED flag not needed).
	SessionKey() []byte

	// ConnectionID returns the stable connection identifier for this session.
	// Used for migration (HANDSHAKE AddressMigration) and packet-level replay protection.
	// Returns a zero ConnectionID if not assigned.
	ConnectionID() ConnectionID

	// CongestionWindow returns the current congestion window in bytes.
	// Used by applications for adaptive behavior (e.g., screen quality, chunk sizing).
	// Returns 0 if the transport handles congestion natively (e.g., QUIC).
	CongestionWindow() int64

	// Protocol returns the underlying transport protocol.
	Protocol() Protocol

	// Metrics returns current session-level metrics for observability.
	// Used by STATS frame generation and monitoring endpoints.
	Metrics() SessionMetrics
}

// ProbeRoute describes one path for parallel probing.
// Used by dispatch.SessionFinder.FindRoutes and the parallel probe launcher.
type ProbeRoute struct {
	Session      Session  // session to send the probe to (first hop)
	NodeID       string   // first-hop nodeID
	TargetNodeID string   // ultimate destination (handler owner)
	RouteList    []string // remaining hops after first hop [next, ..., target]
}

// SessionMetrics holds observable session-level statistics.
// Exposed via the STATS frame type and monitoring API endpoints.
type SessionMetrics struct {
	RTT           time.Duration // smoothed RTT
	LossPercent   float64       // estimated packet loss percentage (0-100)
	CWND          int64         // current congestion window (bytes)
	PacingRate    float64       // current pacing rate (bytes/sec), 0 if no pacing
	Retransmits   uint64        // total frames retransmitted
	FramesSent    uint64        // total frames sent
	FramesRecv    uint64        // total frames received
	BytesSent     uint64        // total payload bytes sent
	BytesRecv     uint64        // total payload bytes received
	ActiveStreams int           // number of open streams
	DroppedFrames uint64        // frames dropped (buffer full, expired, replay)
	FECRecoveries uint64        // frames recovered via FEC (without retransmit)
	ReplayRejects uint64        // frames rejected by anti-replay window (deprecated: now equals ReplayDuplicates + ReplayAncient — kept for back-compat)

	// Security observability counters. See _SECURITY.md for the attack
	// classes each addresses.
	SuspiciousACKs   uint64 // §3.2  — Composite ACKs rejected as malformed/oversized
	FECGroupsEvicted uint64 // §3.5  — FEC groups evicted by count/age pruning
	StreamRefused    uint64 // §3.12 — incoming stream opens rejected at cap
	SeqNoWraps       uint64 // §3.3  — SeqNo jumps rejected as wrap-attack
	RecvWindowDrops  uint64 //       — reorder-buffer overflow drops (total across streams)
	DecryptErrors    uint64 //       — decryption failures on incoming packets
	InboxDrops       uint64 //       — packets dropped because the session inbox was full

	// Anti-replay classification counters (Classify/Commit split). Total
	// ReplayRejects is the sum of these — surfaced separately because
	// the operational meaning is different:
	//
	// ReplayDuplicates = legitimate retransmits the sender re-sent
	//   because its ACK was lost / late. NOT abuse. A high value
	//   signals a lossy ACK-direction path (reverse channel) and is
	//   the most useful per-stream observable for diagnosing
	//   asymmetric loss. Consumers should display this as a quality
	//   signal (path stress), not a security event.
	//
	// ReplayAncient = SeqNos below the reliability window bottom. A
	//   legitimate sender cannot produce these inside one rekey
	//   window, so an elevated count is genuinely anomalous (buggy
	//   peer, broken send-window bookkeeping, or active replay attack
	//   with stale captured frames). DOES feed abuse score.
	//
	// SeqNoWraps (above) is the third class — forward jumps past
	// half the uint32 space, kept separate because it has an even
	// stricter "definitely-attack" interpretation.
	ReplayDuplicates uint64 // legitimate retransmit count (informational, not abuse)
	ReplayAncient    uint64 // out-of-window drops (abuse-eligible)

	// Per-stream observe metrics (ACK-observe mode — pure observation, no enforcement).
	// Available on all transport types. Keyed by stream ID.
	StreamObserve map[uint64]StreamObserveData `json:"streamObserve,omitempty"`

	// Send-path / ACK-engine observability counters. All are per-session
	// totals since session create; Library surfaces them via MeshMetrics
	// under the `aether_*` namespace.
	//
	// CanSendFalseReenqueues: writeLoop re-enqueued a frame because
	// CUBIC CanSend(inFlight+frameSize) returned false. Elevated counts
	// during a latency spike window indicate the congestion controller
	// is throttling the send path.
	//
	// WakeOnAckCalls: every ACK arrival calls sched.Wake()
	// unconditionally. The delta between this and CanSendFalseReenqueues
	// approximates how often the writeLoop blocked on a wake that the
	// ACK has now provided — a missed-wake/park-race signal.
	//
	// AckEmitDelayTimer: ACKs emitted because the adaptive delayed-ACK
	// timer fired with no immediate trigger applied. The timer caps at
	// min(MaxDelay, SRTT/4); a high ratio of delay-timer vs immediate
	// emits on a low-RTT path indicates the timer is the dominant ACK
	// trigger and the delayed-ACK floor is the latency source. Compare
	// against AckEmitImmediate.
	//
	// AckEmitImmediate: ACKs emitted by immediate triggers (gap
	// detected / control stream / first-after-idle / max-packets).
	// High immediate-vs-timer ratio = healthy ACK-driven flow control.
	//
	// AckEmitDuplicate: ACKs emitted because OnDuplicateReceived
	// forced an immediate flush (legitimate retransmit landed in the
	// replay window). Elevated counts = lossy ACK-direction path; the
	// sender keeps retransmitting frames whose ACKs were lost.
	CanSendFalseReenqueues uint64 `json:"canSendFalseReenqueues,omitempty"`
	WakeOnAckCalls         uint64 `json:"wakeOnAckCalls,omitempty"`
	AckEmitDelayTimer      uint64 `json:"ackEmitDelayTimer,omitempty"`
	AckEmitImmediate       uint64 `json:"ackEmitImmediate,omitempty"`
	AckEmitDuplicate       uint64 `json:"ackEmitDuplicate,omitempty"`

	// RTT percentile distribution from the session's primary control
	// stream over the most recent 256 samples. SRTT (above) is the
	// EMA — "typical RTT right now". These three percentiles describe
	// the recent latency distribution so operators can distinguish a
	// uniformly-fast path from one that occasionally tails into the
	// hundreds of milliseconds. Zero when no samples have been
	// recorded yet on the chosen control stream.
	RttP50 time.Duration `json:"rttP50Ns,omitempty"`
	RttP95 time.Duration `json:"rttP95Ns,omitempty"`
	RttP99 time.Duration `json:"rttP99Ns,omitempty"`

	// HealthSRTTUs is the smoothed RTT (SRTT) reported by the
	// session's health.Monitor — populated by Pong arrivals via the
	// WaitForActivityPing → RecordPingSent → RecordPongRecv chain (S2
	// fix in aether v0.0.83 ping.go). Independent of the per-stream
	// RTT estimator (RttP50/95/99) which only fires on DATA-frame ACKs.
	// On low-traffic sessions (no data sent) RttP50 stays 0 while
	// HealthSRTTUs still surfaces the ping-derived liveness RTT.
	// Zero when the session's health.Monitor has never received a
	// matching Pong (also the pre-S2-fix behaviour fleet-wide).
	HealthSRTTUs uint64 `json:"healthSrttUs,omitempty"`

	// Observability histograms surfaced as p50/p99 microseconds — the
	// minimum cardinality that lets operators localize the bimodal RPC
	// latency tail the fleet has been seeing. Source histograms live on
	// NoiseSession; consumers (Library MeshMetrics, dashboards) read
	// them via STATS frames + monitoring endpoints.
	//
	// OBS-1: time inside the underlying transport's write call. High
	// p99 here points at kernel send-buffer pressure / TLS encode /
	// WebSocket framing — i.e. cost *outside* aether's control.
	WriteSyscallP50Us uint64 `json:"writeSyscallP50Us,omitempty"`
	WriteSyscallP99Us uint64 `json:"writeSyscallP99Us,omitempty"`
	// OBS-2: time the writeLoop spent parked on its wake channel.
	// High p99 with a low p50 is the classic "idle stream with bursts"
	// shape; sustained-high p50 indicates app-side send pacing is the
	// throughput bottleneck (not aether's congestion control).
	WriteloopParkP50Us uint64 `json:"writeloopParkP50Us,omitempty"`
	WriteloopParkP99Us uint64 `json:"writeloopParkP99Us,omitempty"`
	// OBS-4: duration that CUBIC.CanSend stayed false in a run of
	// consecutive writeLoop re-enqueue iterations. Paired with the
	// CanSendFalseReenqueues counter (above) — counter gives the
	// frequency, percentiles give the per-event severity.
	CubicCwndBlockP50Us uint64 `json:"cubicCwndBlockP50Us,omitempty"`
	CubicCwndBlockP99Us uint64 `json:"cubicCwndBlockP99Us,omitempty"`
	// OBS-5: time flow.StreamWindow.Consume spent blocked on the
	// credit semaphore. Skips samples below ~100µs (uncontended fast
	// path) so the distribution reflects real grant starvation, not
	// semaphore-acquire overhead. Elevated p99 here means the peer's
	// WINDOW_UPDATE channel is the bottleneck — usually a lossy ACK-
	// direction path or a malfunctioning auto-tuner.
	GrantStarveP50Us uint64 `json:"grantStarveP50Us,omitempty"`
	GrantStarveP99Us uint64 `json:"grantStarveP99Us,omitempty"`
	// OBS-10: cwnd utilisation per-mille (inFlight/cwnd * 1000)
	// sampled every 16th write. p50 ≈ 1000 = cwnd-bound for most
	// sends; p50 << 1000 = app-bound (the cwnd is bigger than the
	// session needs). p99 close to 1000 with low p50 = bursty cwnd-
	// bound spikes inside an otherwise app-bound regime.
	CwndUtilP50Permille uint32 `json:"cwndUtilP50Permille,omitempty"`
	CwndUtilP99Permille uint32 `json:"cwndUtilP99Permille,omitempty"`
	// OBS-11: loss-recovery counters. TLPFiresTotal counts every
	// successfully-enqueued Tail Loss Probe; RACKMarksTotal counts
	// every seq RACK declared lost. High TLP/RACK ratio = tail-
	// recovery dominated (app pacing); low ratio = fast-recovery
	// dominated (genuine packet loss).
	TLPFiresTotal  uint64 `json:"tlpFiresTotal,omitempty"`
	RACKMarksTotal uint64 `json:"rackMarksTotal,omitempty"`
	// OBS-15: noise send-cipher rekey telemetry. RekeyTotal is the
	// lifetime count of send-side rekeys on this session (bumped inside
	// RekeyTracker.ResetSend); RekeyBytesSinceLast is the rolling byte
	// count since the last rekey reset. Together they let the operator
	// distinguish "byte-threshold triggered" (steady throughput, total
	// climbs) from "time-threshold triggered" (long idle, bytes-since-
	// last stays small but total climbs). Zero on non-noise adapters —
	// TCP / QUIC sessions don't ratchet through the noise rekey path.
	RekeyTotal          uint64 `json:"rekeyTotal,omitempty"`
	RekeyBytesSinceLast uint64 `json:"rekeyBytesSinceLast,omitempty"`
	// OBS-13: recv-window head-of-line-block latency distribution. Each
	// buffered frame records (deliveryTime − bufferArrivalTime) when it is
	// flushed after its predecessor(s) arrive. Zero when no reordering has
	// occurred. Paired with RecvWindowDrops: drops are the extreme end of
	// the same distribution (frames that blocked long enough to be evicted
	// rather than delivered). Elevated p99 with a low p50 is the "occasional
	// burst reordering" shape; elevated p50 indicates sustained reordering
	// (lossy or heavily misordered path).
	RecvWindowHOLP50Us uint64 `json:"recvWindowHolP50Us,omitempty"`
	RecvWindowHOLP99Us uint64 `json:"recvWindowHolP99Us,omitempty"`
	// OBS-14: caller-block latency distribution for Stream.Send. Each
	// call records wall-clock from entry to return — the time the
	// application thread spent BLOCKED inside Send (window.Consume +
	// connWindow.Consume + sendSingleFrame). Distinct from
	// WriteloopParkP*Us (OBS-2), which measures the writeLoop's internal
	// park on its wake channel: that's the sender-side scheduler view;
	// this is the application-facing view of "how long did my Send
	// block". Samples below ~50µs are skipped (uncontended fast path)
	// and counted in StreamSendFastTotal instead. Elevated p99 here with
	// a healthy WriteloopPark*Us indicates the flow-control credit
	// semaphore — not the wire — is the application-facing latency
	// source; elevated p50 indicates sustained credit starvation across
	// most sends on the session.
	StreamSendBlockP50Us uint64 `json:"streamSendBlockP50Us,omitempty"`
	StreamSendBlockP99Us uint64 `json:"streamSendBlockP99Us,omitempty"`
	// StreamSendFastTotal counts every Stream.Send call that completed
	// faster than the OBS-14 floor (i.e. the fast path, no credit-
	// starvation block). Paired with StreamSendBlockP*Us, this gives the
	// operator the "how many sends were uncontended" denominator that
	// would otherwise be hidden by the percentile-only readout.
	StreamSendFastTotal uint64 `json:"streamSendFastTotal,omitempty"`
	// OBS-14b: per-phase decomposition of the StreamSendBlock total. Each
	// percentile pair attributes the application-facing send latency to a
	// specific phase of the Send hot path:
	//   - PerStreamWindowWait — block in st.window.Consume (per-stream
	//     credit; blocks waiting for the peer's WINDOW_UPDATE)
	//   - ConnWindowWait — block in st.session.connWindow.Consume
	//     (per-conn credit; typically non-blocking unless cap is reached)
	//   - PostCreditSendUs — wall-clock from credit-acquired to Send
	//     return (covers encrypt + write_syscall + writeloop_park)
	// The three histograms share the same below-floor skip as
	// StreamSendBlock — phase durations below streamSendBlockFloor are
	// not recorded so the fast path doesn't dominate the distribution.
	// Sum approximation: StreamSendBlock ≈ PerStreamWindowWait +
	// ConnWindowWait + PostCreditSend (within rounding + fragment loop
	// overhead). Use the three sub-histograms to attribute which phase
	// is starving when StreamSendBlock is elevated.
	PerStreamWindowWaitP50Us uint64 `json:"perStreamWindowWaitP50Us,omitempty"`
	PerStreamWindowWaitP99Us uint64 `json:"perStreamWindowWaitP99Us,omitempty"`
	ConnWindowWaitP50Us      uint64 `json:"connWindowWaitP50Us,omitempty"`
	ConnWindowWaitP99Us      uint64 `json:"connWindowWaitP99Us,omitempty"`
	PostCreditSendP50Us      uint64 `json:"postCreditSendP50Us,omitempty"`
	PostCreditSendP99Us      uint64 `json:"postCreditSendP99Us,omitempty"`
	// OBS-18: per-decrypt AEAD latency distribution (microseconds). Each
	// recv-side noise Decrypt call records its wall-clock cost; the
	// percentile readout exposes the bimodal split that single-mean
	// averages hide. On a healthy CPU-uncontended host p50 and p99 both
	// sit in the few-µs tier; under sustained CPU saturation the decrypt
	// goroutine queues behind other work and p99 climbs into the
	// millisecond range while p50 stays µs — that asymmetric shape is
	// the canonical signal to scale up or shed load. Sustained ms p50
	// indicates ongoing starvation, not just bursts. Zero on non-noise
	// adapters (test loopback / TCP / QUIC) — only the noise/ session
	// path runs AEAD per packet on the recv hot path.
	DecryptLatencyP50Us uint64 `json:"decryptLatencyP50Us,omitempty"`
	DecryptLatencyP99Us uint64 `json:"decryptLatencyP99Us,omitempty"`
	// OBS-9: scheduler queue-depth distribution. Sampled on every wake
	// signal (Enqueue / EnqueueProbe / external Wake) and on every
	// writeLoop pre-park observation. Depth = total frames queued
	// across all streams + any pending TLP probes. Sustained-high p50
	// means work piles up faster than the writeLoop can drain it
	// (cwnd-bound or syscall-bound); p99 >> p50 indicates bursty
	// arrivals that the writeLoop catches up on between bursts;
	// near-zero on both means the queue is consistently drained as
	// fast as it fills (healthy regime). Zero on transports that
	// haven't wired the histogram into their scheduler (any adapter
	// other than the noise session today).
	SchedulerDepthP50 uint32 `json:"schedulerDepthP50,omitempty"`
	SchedulerDepthP99 uint32 `json:"schedulerDepthP99,omitempty"`

	// TLPResetTotal counts every time the session-level STALL-DETECT
	// path fires its false-positive recovery — i.e. the stall
	// detector declared "no progress" but the probe-before-close
	// Ping then succeeded and the recovery code reset per-stream
	// TLP exhaustion counters. Cumulative since session create.
	//
	// Paired with TLPFiresTotal: a high TLPResetTotal:TLPFiresTotal
	// ratio means most TLPs are firing because of stall-detect
	// rescue (path is flaky, not genuinely lossy). Multipath
	// surfaces it through aether_tlp_reset_total; the connection
	// manager that owns the multipath.Manager forwards the same
	// signal into Manager.RecordTLPReset for the PathFlapping
	// demote tier (see multipath/manager.go).
	//
	// Zero on non-noise transports (TCP / QUIC / in-process fakes
	// have no STALL-DETECT path).
	TLPResetTotal uint64 `json:"tlpResetTotal,omitempty"`

	// PathFlappingCount surfaces multipath.Manager.PathFlappingCount
	// at the moment Metrics() is read. Cumulative summation across
	// a peer's paths happens at the Library layer (it owns the
	// per-peer Manager). The field is on SessionMetrics rather than
	// a separate getter so existing observability that snapshots
	// Metrics() once per scrape picks up the value for free.
	//
	// Zero when the session is not registered with any multipath
	// Manager (single-path peer), OR when none of the manager's
	// paths are currently in PathFlapping.
	PathFlappingCount uint32 `json:"pathFlappingCount,omitempty"`
}

// StreamObserveData holds per-stream observation metrics from the ObserveEngine.
type StreamObserveData struct {
	PacketsReceived      int64  `json:"packetsReceived"`
	BytesReceived        int64  `json:"bytesReceived"`
	HighestSeqNo         uint32 `json:"highestSeqNo"`
	GapCount             int64  `json:"gapCount"`
	ReorderCount         int64  `json:"reorderCount"`
	MaxReorderDistance   int    `json:"maxReorderDistance"`
	LossEstimatePermille int    `json:"lossEstimatePermille"`
	JitterUs             int64  `json:"jitterUs"`
}

// Stream represents a single logical data channel within an Session.
// Streams are independent — failure of one stream does not affect others.
type Stream interface {
	// StreamID returns the stream identifier.
	StreamID() uint64

	// Send sends application data on this stream.
	// Blocks until the data is accepted by the reliability/flow control layer.
	// Returns immediately for unreliable streams if the send buffer is available.
	Send(ctx context.Context, data []byte) error

	// Receive reads the next delivered payload from this stream.
	// For ordered streams, payloads arrive in sequence. For unordered, any order.
	// For sequenced streams, only the latest payload is returned (older ones dropped).
	Receive(ctx context.Context) ([]byte, error)

	// Close sends a FIN (graceful close) and waits for the peer's FIN.
	// After Close, no more Send calls are allowed. Receive continues until peer's FIN.
	Close() error

	// Reset aborts the stream immediately with a reason code.
	// Both sides receive an error on their next Send/Receive.
	Reset(reason ResetReason) error

	// SetPriority changes the stream's scheduling weight and dependency.
	// Takes effect on the next frame sent.
	SetPriority(weight uint8, dependency uint64)

	// Config returns the stream's configuration (reliability, priority, etc.).
	Config() StreamConfig

	// IsOpen returns true if the stream is in the Open or HalfClosed state.
	IsOpen() bool

	// Conn returns a net.Conn view of this stream for byte-stream semantics.
	// Enables io.Copy, bufio.Scanner, http.Serve, and any standard Go I/O
	// pattern over Aether streams — the "virtual wire" abstraction.
	// The returned net.Conn is cached per stream (multiple calls return same conn).
	Conn() net.Conn
}

// StreamConfig holds the parameters for opening a new stream.
type StreamConfig struct {
	// StreamID is the application-defined stream identifier.
	// Well-known IDs: 0=gossip, 1=RPC, 2=keepalive, 3=control.
	// Application streams should use IDs >= 100.
	StreamID uint64

	// Reliability defines the delivery guarantee for this stream.
	Reliability Reliability

	// Priority is the initial WFQ scheduling weight (1-255).
	// Higher weight = more bandwidth share relative to siblings.
	Priority uint8

	// Dependency is the parent stream ID for priority inheritance.
	// 0 = root (no dependency).
	Dependency uint64

	// LatencyClass defines the scheduling priority class (REALTIME/INTERACTIVE/BULK).
	// Strict priority between classes. WFQ by weight within class.
	// Default: determined by DefaultLatencyClass(StreamID).
	LatencyClass LatencyClass

	// MaxAge is the maximum frame age before delivery is skipped (deadline-based reliability).
	// 0 = no deadline (deliver regardless of age).
	// Non-zero: sender skips retransmit if expired, receiver drops if expired.
	// Use for: screen deltas (100ms), input events (50ms), telemetry (10s).
	MaxAge time.Duration

	// InitialCredit sets the flow control credit window for this stream.
	// 0 = use DefaultStreamCredit (256KB). Non-zero overrides the default.
	// File transfer streams should use 2MB+ for throughput (40MB/s at 50ms RTT).
	InitialCredit int64

	// MaxCredit bounds how large the auto-tuner may grow this stream's
	// send window. 0 = use the package-level MaxGrowableWindow ceiling.
	// Streams that carry small messages (gossip, control) should set a
	// small ceiling to bound worst-case per-stream memory; streams that
	// carry bulk data should leave this at 0 to let the BDP heuristic
	// take them up to the package default.
	MaxCredit int64

	// FECLevel sets the forward error correction level for this stream.
	// Default: FECBasicXOR for Noise-UDP, FECNone for others.
	FECLevel uint8

	// Compressed enables per-frame DEFLATE compression on this stream.
	Compressed bool

	// Encrypted enables per-frame AEAD encryption on this stream.
	// Only needed when the transport doesn't provide native encryption
	// (e.g., plain WebSocket without TLS, or relay scenarios).
	Encrypted bool
}

// DefaultStreamConfig returns a sensible default configuration for application streams.
func DefaultStreamConfig(streamID uint64) StreamConfig {
	return StreamConfig{
		StreamID:    streamID,
		Reliability: ReliableOrdered,
		Priority:    128,
		Dependency:  0,
		Compressed:  false,
		Encrypted:   false,
	}
}
