/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
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
	// their own channel + push-mode shim. handleOpen
	// calls acceptor.Notify on every accepted
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

	// FEC state lives on each stream (noiseStream.fec). fecCached is what all of
	// this session's decoders hold together, the count each one's budget compares
	// with fecSessionCacheBytes. fecEvictedLeft keeps the undecided groups of
	// streams that have gone, and fecRecovered the frames decoders rebuilt, for
	// Metrics.
	fecCached      atomic.Int64
	fecEvictedLeft atomic.Uint64
	fecRecovered   atomic.Uint64

	// resetGrants keeps, for a stream a RESET of either side's ended here, what this
	// side's consumer had returned of the peer's sends on it (noteResetGrants), the
	// Consumed every acknowledgment of a copy of the peer's RESET of that stream
	// states (handleReset). awaitingStatement holds each stream whose RESET this side
	// wrote and whose connection charge waits for the peer's statement: the
	// acknowledgment (resetAcknowledged) or the peer's crossing RESET (handleReset).
	// Both are keyed by the stream as this side names it (resetKey). Guarded by mu.
	resetGrants       map[resetKey]resetGrant
	awaitingStatement map[resetKey]*noiseStream

	// priorOpened holds, per stream ID, the last stream this side opened under the ID
	// that a RESET of either side ended (noteResetGrants): its generation and what this
	// side's consumer returned of the peer's sends on it, which the ID's next OPEN
	// states (OpenStream, aether.OpenPayload.PriorGeneration) for a peer that still
	// holds that stream. Bounded and swept as resetGrants is. Guarded by mu.
	priorOpened map[uint64]priorStream

	// pendingResets holds every RESET this side wrote and has had no acknowledgment
	// of, keyed by the stream it names (writeReset, resetAcknowledged), which
	// retransmitResets writes again on the reliability tick; pendingByID counts them
	// per stream ID, for resetPendingLocked. pendingStreams is how many of them end a
	// stream (not a refusal): each keeps its stream's place under the session's stream
	// cap (createStream) until its acknowledgment, so no stream's RESET is ever left
	// without a place to wait for its statement. pendingRefusals is the rest, at most
	// the stream cap. pendingResetCount is the map's size, read lock-free so a tick
	// with nothing pending takes no lock. All guarded by mu (the count is written
	// under it).
	pendingResets     map[resetKey]*pendingReset
	pendingByID       map[uint64]int
	pendingStreams    int
	pendingRefusals   int
	pendingResetCount atomic.Int64

	// PMTU discovery (UDP only)
	pmtuProber *pmtu.Prober

	// Connection migration handler
	migrator *migration.Migrator

	// Replay protection is two layers: noise/nonce_window.go (pre-decrypt,
	// per conn) and the per-stream reliability.ReplayWindow
	// (noiseStream.replay, handleData's Classify and Commit). The session
	// holds no replay window of its own.

	// streamRefused counts every stream open rejected because the
	// MaxConcurrentStreams cap is reached — both peer-initiated OPENs
	// (and implicit-OPENs piggy-backed on the first DATA frame) AND
	// locally-initiated OpenStream calls. Operators reading this
	// counter should NOT treat a rising value as exclusively-
	// adversarial peer behaviour — a leak in the local caller (e.g.
	// a stream pool not releasing streams fast enough) also bumps the
	// counter.
	streamRefused uint64

	// writeLoop wake telemetry — pair these two to diagnose missed
	// wakes during cwnd backoff:
	//   cansendFalseReenqueues — incremented every time the writeLoop's
	//     CanSend check refuses the frame it holds.
	//   wakeOnAckCalls — incremented every time handleACK wakes the
	//     scheduler (every ACK, unconditionally).
	// Surfaced through Metrics(); the consumer that sums a session's
	// stats adds them across sessions.
	cansendFalseReenqueues uint64
	wakeOnAckCalls         uint64

	// Per-session delivery-side flow-control telemetry. enqueueDelivery and
	// enqueueControl record every stream's messages in this shared
	// DeliveryStats, so receive-path delivery / drop / bytes-dropped counters
	// are session-aggregate.
	// Lock-free atomics inside DeliveryStats let the readLoop (single
	// writer per counter per call) and monitoring goroutines (the
	// DeliveryStats() accessor) coexist without synchronisation; the
	// consumer that sums a session's stats reads it through that
	// accessor.
	deliveryStats DeliveryStats

	// bytesSentSinceLastCE is the per-ACK-interval upper bound for the
	// peer's CEBytes claim. Each outbound wire byte (emitFrameLocked)
	// adds to this counter; each inbound CompositeACK carrying an
	// ECN-piggyback drains it via atomic.Swap and uses the drained
	// value as the maximum-plausible CE claim for that interval. The
	// claim is in the same bytes: the peer's noiseConn counts a CE-marked
	// datagram as the DATA packet payload it decrypts, which is the
	// buffer emitFrameLocked passed to conn.Write.
	// Without this cap a bad-faith peer can advertise CEBytes far
	// larger than anything they could have actually received from us,
	// driving our congestion controller into spurious cwnd collapses
	// (handleACK's per-ACK ackedBytes cap doesn't help when the peer
	// spreads inflated claims across pure-dup ACKs where ackedBytes=0).
	// Overruns are clamped to the drained budget and flagged through
	// reportAbuse(ReasonACKValidation) so the abuse scorer can
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
	// the consumer that owns the multipath.Manager (outside this
	// repository) polls the delta and forwards each event into
	// Manager.RecordTLPReset to drive the PathFlapping demote tier. See
	// multipath/manager.go for the demote semantics.
	tlpResetTotal uint64

	// retransmitEvicted counts frames dropped from a stream's retransmit
	// queue (byte-cap eviction, deadline, or max-retries) — each is a
	// reliable frame that lost its RTO safety net. Bumped by the onEvict
	// hook createStream installs.
	retransmitEvicted uint64

	// Observability histograms (see metrics/duration_hist.go). All four
	// histograms are populated on writeLoop / writeFrame hot paths;
	// PercentileSnapshot is read once per Metrics() call (which is a
	// monitoring-cadence operation, not a per-frame one).
	//
	//   writeSyscallHist    — time spent inside the conn.Write call
	//                         (kernel send path / TLS encode / WS write).
	//   writeloopParkHist   — time the writeLoop blocked parked on
	//                         its wake channel.
	//   cwndBlockHist       — duration that CUBIC's CanSend stayed
	//                         false on consecutive writeLoop iterations
	//                         (block-entry to next successful CanSend).
	//   grantStarveHist     — time flow.StreamWindow.Consume blocked
	//                         on the credit semaphore. Shared by every
	//                         stream on the session via SetGrantStarveHist.
	//   cwndUtilRing        — per-mille (inFlight/cwnd) samples
	//                         captured every cwndUtilSamplePeriod writes.
	//   recvWindowHOLHist   — recv-window head-of-line-block latency.
	//                         Time between a frame's buffer arrival and its
	//                         ordered delivery to the application. Shared
	//                         across all streams on the session (same pattern
	//                         as grantStarveHist) via SetHOLHist at
	//                         createStream time.
	//   streamSendBlockHist — caller-block latency inside noiseStream.Send.
	//                         Wall-clock time the application spent inside the
	//                         Send call (window.Consume + connWindow.Consume +
	//                         sendSingleFrame) from entry to return. Distinct
	//                         from writeloopParkHist, which measures
	//                         the writeLoop's internal park on its wake
	//                         channel — that's the sender-side scheduler view;
	//                         this is the application-facing view of "how long
	//                         did my Send block". Shared across all streams
	//                         on the session via the streamSendBlockHist ptr
	//                         field on noiseStream (set at createStream).
	//                         Samples below streamSendBlockFloor are skipped
	//                         and counted in streamSendFastTotal instead — the
	//                         same fast-path skip pattern as
	//                         grantStarveHist.
	writeSyscallHist    metrics.DurationHist
	writeloopParkHist   metrics.DurationHist
	cwndBlockHist       metrics.DurationHist
	grantStarveHist     metrics.DurationHist
	cwndUtilRing        metrics.PermilleRing
	recvWindowHOLHist   metrics.DurationHist
	streamSendBlockHist metrics.DurationHist
	// Per-phase decomposition of streamSendBlockHist. Recorded
	// at each phase boundary inside noiseStream.Send so operators can
	// attribute application-facing send latency to per-stream credit
	// starvation vs per-conn credit starvation vs the post-credit
	// encrypt/write/park path. Same fast-path skip as streamSendBlockHist
	// applies — phase durations below streamSendBlockFloor are not
	// recorded so the fast path doesn't dominate.
	perStreamWindowWaitHist metrics.DurationHist
	connWindowWaitHist      metrics.DurationHist
	postCreditSendHist      metrics.DurationHist
	// schedulerDepthRing — scheduler queue-depth distribution.
	// Wired into s.sched via SetDepthHist at session construction so
	// every Enqueue / EnqueueProbe / external Wake and every writeLoop
	// pre-park ObserveDepth() pushes the current queue depth into the
	// ring. PercentileSnapshot is read once per Metrics() call.
	schedulerDepthRing metrics.Uint32Ring

	// streamSendFastTotal counts the number of noiseStream.Send calls that
	// completed faster than streamSendBlockFloor. These calls bypass the
	// streamSendBlockHist Record — recording every microsecond-fast send
	// would dominate the distribution with uncontended noise and bury the
	// real caller-block signal streamSendBlockHist exists to surface. The
	// fast-total counter preserves the "how many sends were uncontended"
	// signal that would otherwise be lost. Same pattern as the fast-path
	// skip in flow.StreamWindow.Consume.
	streamSendFastTotal atomic.Uint64

	// cwndUtilCounter sequences writes so we sample cwnd-util every
	// cwndUtilSamplePeriod-th send. The writeLoop (noise_reliability.go,
	// atomic.AddUint64) is its one writer; the atomic keeps that sampling
	// correct if a second writer is ever added. Wrap is harmless — we only
	// inspect counter % period.
	cwndUtilCounter uint64

	// lastOverloadSignal is the UnixNano of signalReceiveOverload's last
	// CONGESTION, so a sustained overload emits one per receiveOverloadInterval.
	lastOverloadSignal atomic.Int64

	// inFlightBytes is the session's count of wire bytes in flight: for every
	// frame written and not yet acked in every stream's SendWindow, the bytes
	// conn.Write took at its first write (SendEntry.InFlightBytes). A frame
	// still in the scheduler holds none of it, so CanSend compares the window
	// with what is on the wire and a burst behind the gate cannot close the
	// gate on itself. Each stream's SendWindow is wired into this counter via
	// SetSessionInFlightCounter in createStream, so SendWindow.MarkWritten
	// charges it and every removal (the ACK paths; ReleaseInFlight when the
	// stream leaves s.streams) gives the same count back. Its readers are
	// totalInFlightBytes: the writeLoop's CanSend gate (one atomic.Load, no
	// walk of every stream's window under per-stream locks), the
	// cwnd-utilisation sample, and the pipe at handleACK and the RACK tick.
	//
	// Consistency: each mutation is sequenced under the per-stream
	// SendWindow.mu, so the counter never under-reports relative to the
	// per-stream entries-map content.
	inFlightBytes atomic.Int64

	// Session-aggregate frame and byte counters consumed by Metrics().
	// bytesSent/framesSent are bumped in countFrameSent, once per write by
	// the write loop and by writeFrame (counts every send attempt — see
	// countFrameSent for the at-attempt-vs-at-success rationale).
	// bytesRecv/framesRecv are bumped at dispatchFrame on the receive
	// path. Payload-byte semantics (matches aether.SessionMetrics.BytesSent
	// / BytesRecv): a frame's payload before deflate and encryption, on a
	// retransmit too, not on-wire bytes including frame headers.
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	framesSent atomic.Uint64
	framesRecv atomic.Uint64

	// appBytesDelivered counts payload bytes actually DELIVERED to an
	// application DATA stream (handleData / TypeDATA), NOT dispatch-path
	// bytesRecv (which counts every frame incl. control/gossip/ACK). This
	// is the un-gameable "this is a real, delivering mesh member" signal
	// reportAbuse reads to place a session in its forensic-only tier: a
	// peer flooding malformed frames / bad ACKs never reaches app delivery
	// (malformed fails Validate; bad-ACK hits TypeACK not handleData), so
	// it can never shelter into that tier. LastActivity and bytesRecv both
	// refresh PRE-Validate and are gameable; app delivery is not.
	appBytesDelivered atomic.Uint64

	// forensicSuppressed counts guard-covered abuse events (ack-validation /
	// malformed-frame) that were RECORDED for observability but deliberately
	// NOT scored/closed because the session is established + grade-A (past
	// warmup + actively app-delivering). Surfaced so triage can still see a
	// genuine post-warmup attack that reportAbuse intentionally stops
	// closing — every event stays recorded without arming the blacklist
	// (which would relocate the reap to a reconnect-lockout).
	forensicSuppressed atomic.Uint64

	// lastPeerStats stores the most-recent STATS frame the peer emitted.
	// Updated by handleStats (every ~5s per the peer's reliabilityTick).
	// Read-only consumers (the multipath quality scorer, the consumer that
	// sums a session's stats) call LastPeerStats() to get a snapshot.
	// atomic.Pointer for lock-free readers; nil until the peer's first
	// STATS frame arrives.
	lastPeerStats atomic.Pointer[aether.SessionMetrics]

	// ECN observation from above the Noise conn. RecordCEBytes adds the
	// frame bytes of inbound packets whose IP/IPv6 TOS field carried the CE
	// codepoint (0x03); no caller in this repository calls it, so this
	// counter stays 0 unless a consumer does. The next outbound
	// CompositeACK reads-and-resets it, adds the noiseConn's own counter
	// (noiseConnCE, filled by the noise/ listener's socket-level cmsg
	// plumbing, IP_RECVTOS / IPV6_RECVTCLASS), and carries the total in
	// its CEBytes extension so the sender can call cong.OnCE.
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

	// Peer abuse scoring: one decayed score per peer (abuse.Score). The shared
	// AbuseTracker owns the registry, the threshold-breaker GoAway,
	// and the threshold-breaker session close. Defaults to a
	// per-session registry (1 entry); SetAbuseScoreRegistry replaces
	// it with a shared one so cross-session dashboards can see a
	// peer's behaviour across every connection in one place.
	// `reportAbuse` forwards every misbehaviour-counter site into
	// this tracker.
	abuseTracker *aether.AbuseTracker

	// Stream GC — resets idle streams after opts.StreamIdleTimeout, except IDs below
	// aether.StreamGCExemptBelow and opts.SessionLifetimeStreams; each stream is
	// tracked under its scheduler registration (createStream), reset by
	// resetIdleStream and released by releaseStream.
	streamGC *aether.StreamGC

	// Stall-detection state is per stream (noiseStream.lastBaseACKSeen,
	// lastProgressAtUnixNano, atomic fields): the tracker's lifetime is the
	// stream's (no leak on close), and handleACK on the readLoop writes no
	// session-level map for it.

	// FEC prune scheduling — rate-limit each stream decoder's age prune to ~1/sec.
	// reliabilityTick reads and advances this.
	lastFECPrune time.Time

	// Connection identity
	connID aether.ConnectionID

	// Short header compression, per-stream state: separate encode (tx) and
	// decode (rx) compressors, as TCPSession's. One shared instance would let
	// the peer's inbound sequence numbers and the local outbound sequence
	// numbers cross-contaminate the same StreamCompState.lastSeqNo and
	// SessionCompState.lastSender/lastReceiver, corrupting short-header
	// deltas and identity stamping on bidirectional streams.
	txCompressor *aether.Compressor
	rxCompressor *aether.Compressor

	// frameKey is the per-frame AEAD key and its encryptor, nil until SetSessionKey
	// installs them once on a session that may already be running. Every frame path
	// reads it with one Load and uses what that Load returned: the write side under
	// writeMu (wireSizeLocked, emitFrameLocked), the read loop's decrypt
	// (processIncomingFrame) and SessionKey, none of which takes a lock SetSessionKey
	// could share with the read loop.
	frameKey atomic.Pointer[sessionFrameKey]

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

	// wireVersions is the wire version set the Noise handshake under conn
	// chose, lifted at construction through the noiseConnWireVersions probe
	// and reported by WireVersions. The empty set when conn carries none,
	// which is the case only for a conn no Noise handshake produced, and
	// such a session writes and reads full frames only. Its compressors take
	// their grammar from it. Frozen at construction, read lock-free.
	wireVersions aether.NegotiatedWireVersions

	// fragRecv is what every fragment this session receives must match: the
	// chosen fragment envelope version, the realm conn's handshake bound
	// (noiseConnRealm), the remote PeerID and the peer's pinned incarnation.
	// Every stream's FragmentBuffer checks against it. Set at construction,
	// never replaced.
	fragRecv *FragmentReceiver

	// realmID and realmBound are the realm this session's fragment envelopes
	// carry: the fingerprint of the Noise prologue conn's handshake bound, a
	// mesh session's network key or an over-conn session's grant realm
	// (noise.GrantRealm), unbound for a conn that reports none (an over-conn
	// handshake without a grant, or a test pipe), which then sends and
	// receives no fragments. Frozen at construction, read lock-free.
	realmID    uint32
	realmBound bool

	// streamGenerations numbers every stream object this session creates, so a
	// stream ID opened again carries a higher generation on its fragments than
	// the stream that used the ID before (FragmentBinding.Generation), and a
	// stream this side opens states its number in its OPEN, CLOSE and RESET
	// (noiseStream.incarnation).
	streamGenerations atomic.Uint64

	// admitted is the receive credit this session's streams hold, against the
	// session's ceiling (flow.BoundsProfile.AdmittedCreditCeiling) and, through its parent, against
	// the per-peer ceiling (peerCreditCeiling) across every session to the same
	// peer. createStream reserves a stream's credit here before publishing it;
	// a stream's departure from s.streams releases it; CloseWithError closes
	// the ledger, returning the rest to the peer's. creditPeerShared says the
	// parent is the remote node ID's entry in sessionPeerLedgers, which
	// CloseWithError leaves; false for a session whose parent is its own
	// (newNoiseSession).
	admitted         *creditLedger
	creditPeerShared bool

	// recentlyLeft holds, per stream ID, when a stream that left on both CLOSEs,
	// or whose RESET was acknowledged or not kept to wait for it, stops being a
	// reason to refuse a local OpenStream of its ID (noteLeft, resetAcknowledged,
	// writeReset, reopenQuietLocked). Guarded by s.mu, pruned by
	// sweepRecentlyLeft.
	recentlyLeft map[uint64]time.Time

	// recvMemory is what this session's receive queues hold: recvQueued, which
	// signalReceiveOverload reads, recvCharged, which receiveCeilings'
	// session limit holds the peer to, and the queues of ended streams, which
	// sweepEndedQueues on the reliability tick and makeQueueRoom discard.
	recvMemory
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
//
// remoteNodeID keys the per-peer credit ledger (sessionPeerLedgers), so it
// must be the identity conn's handshake authenticated; a session whose remote
// ID is a stated label is built through newNoiseSession with its own ledger.
func NewNoiseSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *NoiseSession {
	return newNoiseSession(conn, localNodeID, remoteNodeID, opts, true)
}

// newNoiseSession is NewNoiseSession with the choice of per-peer ledger:
// sharedPeer joins the remote node ID's entry in sessionPeerLedgers; false
// gives the session a peer ledger of its own at the same ceiling, for
// wrapPostHandshakeAsSession, whose remote node ID the over-conn handshake
// reports unchecked, and for NewSessionForStatedPeer, whose caller holds only
// the ID the remote stated, since sharing either would let one peer spend
// another's credit.
func newNoiseSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions, sharedPeer bool) *NoiseSession {
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
		connWindow:  flow.NewConnWindow(flow.CurrentBounds().ConnCredit()),
		pacer:       selectPacer(opts),
		// connGrantDebouncer initialized below after s is assigned, because
		// the grantable + sendUpdate bindings reference s itself.
		txCompressor: aether.NewCompressor(),
		rxCompressor: aether.NewCompressor(),
		recentlyLeft: make(map[uint64]time.Time),
	}
	sessionCeiling := flow.CurrentBounds().AdmittedCreditCeiling(opts.MaxConcurrentStreams)
	var peerLedger *creditLedger
	if sharedPeer {
		peerLedger = sessionPeerLedgers.join(remoteNodeID, peerCreditCeiling(sessionCeiling))
		s.creditPeerShared = true
	} else {
		peerLedger = newCreditLedger("peer", peerCreditCeiling(sessionCeiling), nil)
	}
	s.admitted = newCreditLedger("session", sessionCeiling, peerLedger)
	s.joinPeerMemory(remoteNodeID, sharedPeer)
	// The live stream IDs are this side's streams and the peer's, each within the
	// stream cap, so the receive compressor records no more than twice it.
	streamCap := opts.MaxConcurrentStreams
	if streamCap <= 0 {
		streamCap = aether.DefaultMaxConcurrentStreams
	}
	s.rxCompressor.BoundStreams(2 * streamCap)
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
	if wv, ok := conn.(noiseConnWireVersions); ok {
		s.wireVersions = wv.WireVersions()
	}
	if r, ok := conn.(noiseConnRealm); ok {
		s.realmID, s.realmBound = r.RealmID()
	}
	fragmentVersion, _ := s.wireVersions.Version(aether.WireVersionFragment)
	s.fragRecv = NewFragmentReceiver(fragmentVersion, s.realmID, s.realmBound, s.RemotePeerID())
	// The grammar both directions use: short forms only when the handshake
	// chose frame.short. Set before readLoop and writeLoop start.
	s.txCompressor.UseWireVersions(s.wireVersions)
	s.rxCompressor.UseWireVersions(s.wireVersions)

	// Session-wide conn-level grant debouncer. Immediate-flush floor at
	// GrantImmediateFraction of the connection credit so burst patterns don't
	// wait the full coalesce window when the sender is close to the conn-level
	// edge.
	s.connGrantDebouncer = newGrantDebouncer(
		s.connWindow,
		s.sendWindowUpdateAgnostic,
		aether.StreamConnectionLevel,
		int64(float64(flow.CurrentBounds().ConnCredit())*GrantImmediateFraction),
	)

	// Per-StreamID accept dispatch + AcceptStream FIFO — shared
	// implementation in the root aether package. NonBlockingDrop: when the
	// FIFO is full the acceptor refuses the stream (refuseUnaccepted) rather
	// than hold the readLoop, which runs handleOpen. Claimed: the IDs the
	// session's consumers take only by AcceptStreamByID.
	s.acceptor = aether.NewStreamAcceptor(aether.StreamAcceptorConfig{
		Mode:      aether.NonBlockingDrop,
		Closed:    base.CloseSignal(),
		ErrClosed: aether.ErrSessionClosed,
		Refuse:    s.refuseUnaccepted,
		Claimed:   opts.ClaimedStreams,
	})

	// Wire the scheduler-depth histogram so every Enqueue /
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

	// Per-peer abuse scoring. One score registry per session — the
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
	// connID is owned by *BaseSession (initialised by NewBaseSession).
	s.streamGC = aether.NewSessionStreamGCByRegistration(opts, s.resetIdleStream)

	// PMTU prober sends PATH_PROBE frames to discover maximum segment size. size is
	// the MSS under test, and MSSToMaxPayload's payload in a full frame, sealed, is
	// that long on the wire: the probe is exactly the largest frame noiseStream.Send
	// builds at that MSS, so the size a response confirms is the size the path
	// carried, and a session with no frame key sends both 16 bytes shorter.
	s.pmtuProber = pmtu.NewProber(func(probeID uint32, size uint16) error {
		payload := aether.EncodePathProbe(probeID, uint16(MSSToMaxPayload(int(size))-aether.PathProbeMinSize))
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
		return nil, aether.ErrSessionClosed
	default:
	}

	// Stream ID exhaustion check
	if cfg.StreamID > aether.MaxStreamID {
		return nil, fmt.Errorf("stream ID %d exceeds MaxStreamID (%d) — send GOAWAY", cfg.StreamID, aether.MaxStreamID)
	}

	// An FEC level outside the registry is refused, and never read as no FEC.
	if !reliability.ValidFECLevel(cfg.FECLevel) {
		return nil, fmt.Errorf("OpenStream stream=%d: FEC level %d: %w", cfg.StreamID, cfg.FECLevel, aether.ErrFECLevelUnsupported)
	}

	// The stream's own ceiling: an initial credit above it is refused, since
	// flow.NewStreamWindowWithCap would otherwise raise the window's growth
	// ceiling to the initial credit.
	if ceiling := streamCreditCeiling(cfg); cfg.InitialCredit > ceiling {
		return nil, fmt.Errorf("OpenStream stream=%d: initial credit %d above the stream ceiling %d: %w",
			cfg.StreamID, cfg.InitialCredit, ceiling, aether.ErrStreamCreditRefused)
	}
	// The OPEN payload states the credit in four bytes (aether.MaxOpenCredit);
	// a credit it cannot state is refused here, before the stream exists, so
	// the peer never builds a window other than this one.
	if cfg.InitialCredit > aether.MaxOpenCredit {
		return nil, fmt.Errorf("OpenStream stream=%d: initial credit %d above what OPEN states (%d): %w",
			cfg.StreamID, cfg.InitialCredit, aether.MaxOpenCredit, aether.ErrStreamCreditRefused)
	}

	// Locally-initiated open. enforceRemoteCap=false means: enforce
	// the MaxConcurrentStreams cap and the credit reservation but do NOT
	// send a RESET back (no peer to RESET — the caller gets the error
	// directly). Both apply universally so a leaking local caller can't
	// exhaust the session's stream-slot table or its admitted credit. An ID
	// still in use, just left on both CLOSEs or by an acknowledged RESET
	// (reopenQuietLocked), or whose RESET waits for its acknowledgment
	// (resetPendingLocked), is refused too, and no second OPEN goes to the peer.
	st, err := s.createStream(cfg.StreamID, cfg, false, 0)
	if err != nil {
		// Refused. streamRefused counter already incremented inside
		// createStream for a cap or credit refusal. Surface the typed sentinel
		// (ErrStreamCapExhausted, ErrStreamCreditRefused or ErrDuplicateStreamID)
		// so callers can detect it via errors.Is and back off instead of closing
		// the session.
		if errors.Is(err, aether.ErrStreamCapExhausted) {
			cap := s.opts.MaxConcurrentStreams
			if cap <= 0 {
				cap = aether.DefaultMaxConcurrentStreams
			}
			return nil, fmt.Errorf("OpenStream cap=%d: %w", cap, err)
		}
		return nil, fmt.Errorf("OpenStream stream=%d: %w", cfg.StreamID, err)
	}
	recordStreamEvent(st.state, aether.EventSendOpen)

	// Send OPEN frame. It states the credit createStream reserved for the
	// stream, the window's size after flow.NewStreamWindowWithCap resolved the
	// configured credit (zero to the default, a small one up to
	// flow.MinGuaranteedWindow): the peer's handleOpen builds its window and
	// its reservation for the stream from it, so each side's sends on the
	// stream are bounded by the credit the other side holds for them. It states
	// the FEC level the stream runs here, none on a session with FEC disabled,
	// which the peer builds its own state from, and the stream's generation, by
	// which the peer tells this stream's CLOSE and RESET from those of another
	// stream under the ID. It states the last stream this side opened under the ID
	// that a RESET ended, and what this side's consumer returned on it (priorOpened):
	// a peer whose copy of that stream outlived this side's RESET settles it on that
	// statement when this OPEN supersedes it (handleOpen's endSuperseded).
	var fecLevel reliability.FECLevel
	if st.fec != nil {
		fecLevel = st.fec.Level()
	}
	prior := s.takePriorOpened(cfg.StreamID)
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability:     cfg.Reliability,
		Priority:        cfg.Priority,
		Dependency:      cfg.Dependency,
		InitialCredit:   uint32(st.window.CurrentWindow()),
		FECLevel:        uint8(fecLevel),
		Generation:      st.incarnation.Generation,
		PriorGeneration: prior.generation,
		PriorConsumed:   uint64(max(prior.granted, 0)),
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

// AcceptStream delegates to the shared aether.StreamAcceptor, which owns
// the FIFO channel and the per-StreamID dispatch for every adapter. See
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
// Called by handleOpen, the path that produces a remotely-initiated stream.
// Notify's false needs nothing here: the acceptor has already handed the
// stream to refuseUnaccepted.
func (s *NoiseSession) notifyStreamAccepted(st *noiseStream) {
	s.acceptor.Notify(st)
}

// refuseUnaccepted ends a stream the peer opened that the acceptor will not hold
// (aether.StreamAcceptorConfig.Refuse): the FIFO is full, its claimed ID's backlog
// is full, or the acceptor has closed. No consumer will ever read it, so Reset
// writes RESET(ResetRefused), which the opener's Send and Receive read as
// aether.ErrStreamRefused, and releases its stream slot, credit reservation and
// in-flight connection credit (Reset); the RESET states what this side granted,
// so the opener takes back the rest of its charge. What the queue holds is
// thrown away here, not left in the session's budget for the idle sweep
// (sweepEndedQueues) to find: Reset keeps it for a reader, and this stream has
// none. Each of Reset's paths takes the queue out of the credit count
// (settleLocalReset's peerEnded, or releaseCharge for a stream that had left),
// so discard has nothing to grant; what it returns goes to the peer as the
// sweep's discard does, so a charge left by any path is not stranded. The empty
// queue then leaves endedQueues, where Reset's trackEnded put it, as after
// makeQueueRoom's discard.
func (s *NoiseSession) refuseUnaccepted(st aether.Stream) {
	ns, ok := st.(*noiseStream)
	if !ok {
		return
	}
	_ = ns.Reset(aether.ResetRefused)
	s.grantConnCredit(ns.recvQ.discard())
	s.forgetEnded(ns.recvQ)
}

// Identity / Capabilities / Protocol accessors are promoted from the
// embedded *BaseSession.

// Ping sends a PING frame and waits briefly for any inbound activity
// (PONG response or any other frame) before reporting the cached RTT.
//
// The wait is what lets keepalive see a zombie session: writeFrame can
// return nil against a torn-down peer, because s.conn.Write queues the
// frame into a buffered writer that surfaces the network error only
// seconds later, and the cached health.Monitor RTT read straight after a
// successful send is the snapshot from the last completed PING/PONG
// round-trip, which says nothing about the peer now. WaitForActivityPing
// therefore:
//  1. Fast-fails if IsClosed already — avoids a syscall for a known-dead
//     session and lets keepalive distinguish "stuck send" from "session
//     torn down".
//  2. Captures LastActivity before writeFrame, then polls until either
//     ctx fires, IsClosed flips, the Pong for this ping's seqNo arrives,
//     or the deadline (the caller's ctx deadline, else PingDefaultDeadline)
//     is reached, at which point any inbound frame since the ping counts
//     as "alive". A false positive (the peer sent something else inside
//     the deadline) is fine for keepalive; the goal is detecting silence.
func (s *NoiseSession) Ping(ctx context.Context) (time.Duration, error) {
	// The close signal passed is BaseSession.CloseSignal(), the channel
	// SignalClose closes (NoiseSession holds no close channel of its own),
	// so a session torn down mid-probe returns ErrSessionClosed immediately
	// instead of polling LastActivity for the deadline.
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
// s.streams under s.mu (and ended its receive side where appropriate) — this
// helper intentionally does neither, and takes no lock of the session's, so
// resetIdleStream can call it with s.mu held and the RESET/CLOSE exits
// (leaveSession, leaveSchedulerThenSettle) without it.
//
// All operations are idempotent: calling for a streamID that was
// already unregistered is a no-op on both the scheduler and the GC.
//
// reg is the ending stream's scheduler registration (noiseStream.schedReg), which also
// names its stream-GC entry (createStream's RegisterAs): only that registration leaves
// the scheduler and the GC, so a stream the peer opened under the ID after the ending
// stream left s.streams keeps its own (Scheduler.UnregisterRegistration,
// StreamGC.UnregisterRegistration). Zero removes whatever registration the ID has, for
// resetIdleStream's call, under s.mu, for an ID it found no stream under.
func (s *NoiseSession) releaseStream(streamID uint64, reg scheduler.Registration) {
	// The frames Unregister hands back need no credit returned here: a RESET's
	// exit has settled the connection window for all this stream had charged, these
	// included (noiseStream.settleLocalReset, settlePeerReset), and leaveSession's
	// stream has none, its send window having emptied on its CLOSE's ACK.
	if reg != 0 {
		s.sched.UnregisterRegistration(streamID, reg)
	} else {
		s.sched.Unregister(streamID)
	}
	if s.streamGC == nil {
		return
	}
	if reg != 0 {
		s.streamGC.UnregisterRegistration(streamID, uint64(reg))
	} else {
		s.streamGC.Unregister(streamID)
	}
}

// resetIdleStream is the stream GC's reset of the stream it tracked under registration
// (createStream's RegisterAs, the stream's scheduler.Registration) once that stream sat
// idle past the session's StreamIdleTimeout. The sweep has let the entry go before it
// calls this, so between the two the stream can end and the ID be opened again; the
// stream s.streams holds under the ID is reset only when it is the one registration
// names. A later stream under the ID registered after the sweep let the entry go, keeps
// its own entry and is left alone.
//
// With no stream under the ID, the entry was an ID's activity with no stream left
// (dispatchFrame's RecordActivity) or a stream whose exit has not yet released it, and
// releaseStream with no registration clears what the scheduler and the GC still hold
// for the ID. It runs under s.mu, the lock createStream registers a stream under before
// publishing it, so it cannot reach a registration made after the check.
func (s *NoiseSession) resetIdleStream(streamID, registration uint64) {
	dbgNoise.Printf("StreamGC: resetting idle stream %d", streamID)
	s.mu.Lock()
	st, ok := s.streams[streamID]
	if !ok {
		s.releaseStream(streamID, 0)
		s.mu.Unlock()
		return
	}
	if uint64(st.schedReg) != registration {
		s.mu.Unlock()
		return
	}
	delete(s.streams, streamID)
	s.mu.Unlock()
	// Send RESET to the peer. st.Reset releases the stream under its own
	// registration (leaveSchedulerThenSettle) when this is its first exit; when
	// another exit has begun, Reset returns at once and releaseStream here releases
	// it without waiting on that exit. Both name only this stream's registration,
	// so a repeat is a no-op, and the GC side is one already, the sweep having let
	// the entry go.
	_ = st.Reset(aether.ResetTimeout)
	s.releaseStream(streamID, st.schedReg)
}

// sweepEndedQueues is recvMemory.sweepEnded on the reliability tick every ten seconds.
// A discard grants the peer the credit it still had charged for those messages.
func (s *NoiseSession) sweepEndedQueues(now time.Time) {
	s.sweepEnded(now, s.grantConnCredit)
}

// reopenQuietRTOs is how many of the leaving stream's RTOs a stream ID stays closed
// to a local OpenStream after the stream left on both CLOSEs, or after the
// acknowledgment of its RESET came (resetAcknowledged), or after a RESET writeReset
// could not keep was written. A CLOSE and a RESET name the stream they end
// (aether.StreamIncarnation), so a late copy of either meets a new stream under the
// ID and ends nothing of it (handleClose, handleReset). A DATA or ACK frame names no
// stream under its ID: a copy of one still on the path would reach a new stream
// under the ID at the old stream's sequence numbers. A frame and the ACK after it
// take one RTO each way to settle, which three RTOs cover unless every ACK of a run
// of them is lost.
// TODO: name the stream's incarnation on DATA and ACK under a frame grammar
// version, so a late copy of either is refused however late it comes and no ID waits.
const reopenQuietRTOs = 3

// noteLeft records that the stream under id has just left on both CLOSEs
// (noiseStream.leaveIfEnded), starting its ID's quiet time.
func (s *NoiseSession) noteLeft(id uint64, rto time.Duration) {
	s.mu.Lock()
	s.startQuietLocked(id, time.Now(), rto)
	s.mu.Unlock()
}

// reopenQuietLocked reports whether id is in its quiet time (reopenQuietRTOs).
// createStream, under s.mu, refuses a local OpenStream of such an ID; a peer's OPEN
// is not refused, since the peer has seen this side's CLOSE or RESET, and its own
// CLOSE acknowledged.
func (s *NoiseSession) reopenQuietLocked(id uint64) bool {
	until, ok := s.recentlyLeft[id]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(s.recentlyLeft, id)
	return false
}

// sweepRecentlyLeft drops the IDs whose quiet time is over. It runs on the
// reliability tick beside sweepEndedQueues, so the map holds at most the streams
// that left within one tick and one quiet time.
func (s *NoiseSession) sweepRecentlyLeft(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, until := range s.recentlyLeft {
		if now.After(until) {
			delete(s.recentlyLeft, id)
		}
	}
}

// resetKey names a stream among those that have used an ID on the session: the ID
// and the stream's incarnation as this side states it (noiseStream.incarnation). A
// RESET of the peer's names the stream with WriterOpened the other way round
// (peerNamed), its acknowledgment of this side's RESET exactly as that RESET did.
type resetKey struct {
	id  uint64
	inc aether.StreamIncarnation
}

// peerNamed is the key of the stream a frame of the peer's names by inc.
func peerNamed(id uint64, inc aether.StreamIncarnation) resetKey {
	return resetKey{id: id, inc: aether.StreamIncarnation{Generation: inc.Generation, WriterOpened: !inc.WriterOpened}}
}

// resetGrant is what this side's consumer had returned of the peer's sends on a
// stream through connection grants when a RESET ended it here, final from then on
// (recvQueue.peerEnded), and when (noteResetGrants).
type resetGrant struct {
	granted int64
	at      time.Time
}

// priorStream is priorOpened's entry: the generation of the last stream this side
// opened under an ID that a RESET ended, what this side's consumer had returned of the
// peer's sends on it (final at that RESET, recvQueue.peerEnded), and when.
type priorStream struct {
	generation uint64
	granted    int64
	at         time.Time
}

// takePriorOpened returns and forgets the ID's priorOpened entry, the zero value
// (generation 0, no earlier stream) when there is none. OpenStream calls it once
// createStream has published the stream under the ID, so no RESET of another stream
// under the ID can replace the entry in between.
func (s *NoiseSession) takePriorOpened(id uint64) priorStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.priorOpened[id]
	delete(s.priorOpened, id)
	return p
}

// resetGrantLifetime is how long a note answers copies of the peer's RESET. The peer
// writes its RESET again at most resetRetransmitMaxWait apart until an acknowledgment
// reaches it (retransmitResets), and it settles on the first acknowledgment or on
// this side's crossing RESET, so only a copy whose every earlier acknowledgment was
// lost needs the note, and one that comes later than this finds none, as past the
// map's bound: its acknowledgment states Consumed 0, and the peer takes back what
// this side's consumer had returned as well as receiving those grants, which its
// connection window holds at what it has outstanding.
const resetGrantLifetime = 30 * time.Second

// resetRetransmitMaxWait is the longest wait between two copies of a RESET no
// acknowledgment has answered: the wait starts at the RTO of the stream it ended and
// doubles up to this. A RESET is written again until its acknowledgment comes or the
// session ends, since while it waits createStream holds the ID against a local open,
// and a session whose peer answers nothing ends on its idle timeout.
const resetRetransmitMaxWait = 2 * time.Second

// pendingReset is a RESET writeReset wrote that has had no acknowledgment: the
// frame, written again as it is (writeFrame resends its encrypted bytes), the stream
// it ends (nil for a refusal, which ends none), the RTO of that stream, from which
// the quiet time after it is measured, the wait before its next copy and when that
// copy is due. pendingResets keys it by the stream the RESET names, which the
// acknowledgment names too.
type pendingReset struct {
	frame *aether.Frame
	st    *noiseStream
	rto   time.Duration
	wait  time.Duration
	next  time.Time
}

// writeReset writes the RESET p states for streamID and keeps it until the peer
// acknowledges it (resetAcknowledged), writing it again on the reliability tick
// (retransmitResets): a RESET lost on the datagram path would leave the peer's stream
// live under an ID this side opens again, whose frames would then reach the old
// stream's consumer. createStream refuses a local OpenStream of the ID while the
// RESET waits. rto is the RTO of the stream it ends, or of a fresh estimator for a
// refusal, which holds no stream. Reset and sendRefused call it.
//
// st is the stream the RESET ends, nil for a refusal. In one step under s.mu st leaves
// s.streams, its RESET joins pendingResets and st waits in awaitingStatement for the
// peer's statement of what it consumed of st's sends (noiseStream.notePeerConsumed),
// so the stream moves from one count createStream checks against the stream cap
// (s.streams) to the other (pendingStreams) with nothing in between: a stream's RESET
// always has its place to wait, an open past the cap being refused instead
// (createStream), and every RESET of a stream is written again until its own
// acknowledgment. Each RESET is kept under the stream it names, so a later RESET under
// the ID leaves an earlier one waiting. A refusal past the stream cap of waiting
// refusals, which only a peer that acknowledges none of them reaches, is written once
// with the ID's quiet time started, so such a peer cannot grow the map; a refusal ends
// no stream here and settles no credit.
func (s *NoiseSession) writeReset(streamID uint64, p aether.ResetPayload, rto time.Duration, st *noiseStream) error {
	payload := aether.EncodeResetPayload(p)
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	now := time.Now()
	key := resetKey{id: streamID, inc: p.Incarnation}
	s.mu.Lock()
	if s.pendingResets == nil {
		s.pendingResets = make(map[resetKey]*pendingReset)
		s.pendingByID = make(map[uint64]int)
	}
	if st != nil {
		if cur, ok := s.streams[streamID]; ok && cur == st {
			delete(s.streams, streamID)
		}
		if s.awaitingStatement == nil {
			s.awaitingStatement = make(map[resetKey]*noiseStream)
		}
		s.awaitingStatement[key] = st
	}
	_, replaced := s.pendingResets[key]
	if replaced || st != nil || s.pendingRefusals < s.streamCapLocked() {
		s.dropPendingLocked(key)
		s.pendingResets[key] = &pendingReset{frame: frame, st: st, rto: rto, wait: rto, next: now.Add(rto)}
		s.pendingByID[streamID]++
		if st != nil {
			s.pendingStreams++
		} else {
			s.pendingRefusals++
		}
		s.pendingResetCount.Add(1)
	} else {
		s.startQuietLocked(streamID, now, rto)
	}
	s.mu.Unlock()
	return s.writeFrame(frame)
}

// dropPendingLocked takes the RESET kept under key out of pendingResets and its
// counts, and returns it, nil for none. Caller holds s.mu.
func (s *NoiseSession) dropPendingLocked(key resetKey) *pendingReset {
	p, ok := s.pendingResets[key]
	if !ok {
		return nil
	}
	delete(s.pendingResets, key)
	if s.pendingByID[key.id]--; s.pendingByID[key.id] <= 0 {
		delete(s.pendingByID, key.id)
	}
	if p.st != nil {
		s.pendingStreams--
	} else {
		s.pendingRefusals--
	}
	s.pendingResetCount.Add(-1)
	return p
}

// streamCapLocked is the session's MaxConcurrentStreams, the default when the options
// leave it unset: createStream's bound on its streams together with the streams whose
// RESET waits (pendingStreams), and writeReset's on waiting refusals.
func (s *NoiseSession) streamCapLocked() int {
	if limit := s.opts.MaxConcurrentStreams; limit > 0 {
		return limit
	}
	return aether.DefaultMaxConcurrentStreams
}

// resetPendingLocked reports whether a RESET this side wrote under id waits for its
// acknowledgment (writeReset). createStream, under s.mu, refuses a local OpenStream
// of such an ID: the peer may still hold the stream that RESET ends.
func (s *NoiseSession) resetPendingLocked(id uint64) bool {
	return s.pendingByID[id] > 0
}

// resetAcknowledged takes the peer's acknowledgment of a RESET under streamID, which
// names the stream as that RESET did (inc) and states what the peer's consumer had
// returned of this side's sends on it (consumed): the stream waiting for that
// statement (awaitingStatement) settles its connection charge on it, unless the
// peer's crossing RESET settled it first. The RESET it names stops being written,
// gives its stream's place under the stream cap back (pendingStreams), and starts the
// ID's quiet time. handleReset calls it for a RESET flagged FlagACK.
func (s *NoiseSession) resetAcknowledged(streamID uint64, inc aether.StreamIncarnation, consumed uint64) {
	key := resetKey{id: streamID, inc: inc}
	s.mu.Lock()
	st := s.awaitingStatement[key]
	delete(s.awaitingStatement, key)
	if p := s.dropPendingLocked(key); p != nil {
		s.startQuietLocked(streamID, time.Now(), p.rto)
	}
	s.mu.Unlock()
	if st != nil {
		st.notePeerConsumed(consumed)
	}
}

// startQuietLocked starts id's quiet time (reopenQuietRTOs of rto from now). Caller
// holds s.mu.
func (s *NoiseSession) startQuietLocked(id uint64, now time.Time, rto time.Duration) {
	if s.recentlyLeft == nil {
		s.recentlyLeft = make(map[uint64]time.Time)
	}
	s.recentlyLeft[id] = now.Add(reopenQuietRTOs * rto)
}

// retransmitResets writes again every waiting RESET whose wait is over, doubling
// its wait up to resetRetransmitMaxWait. reliabilityTick calls it on every tick; with
// nothing waiting it reads one atomic.
func (s *NoiseSession) retransmitResets(now time.Time) {
	if s.pendingResetCount.Load() == 0 {
		return
	}
	var due []*aether.Frame
	s.mu.Lock()
	for _, p := range s.pendingResets {
		if now.Before(p.next) {
			continue
		}
		p.wait = min(2*p.wait, resetRetransmitMaxWait)
		p.next = now.Add(p.wait)
		due = append(due, p.frame)
	}
	s.mu.Unlock()
	for _, f := range due {
		_ = s.writeFrame(f)
	}
}

// grantConnCredit returns n bytes of the peer's connection credit that no
// Receive will record, through the debouncer Receive's records go through.
func (s *NoiseSession) grantConnCredit(n int64) {
	if n > 0 && s.connGrantDebouncer != nil {
		s.connGrantDebouncer.Record(n)
	}
}

// receiveOverloadInterval spaces signalReceiveOverload's CONGESTION frames; it
// matches the advisory's BackoffMs, so a held overload keeps the hint alive
// and a passing one lets it lapse.
const receiveOverloadInterval = 200 * time.Millisecond

// signalReceiveOverload tells the peer this session's consumers are behind: the
// queues together hold most of the connection credit, the evidence the signal
// names, so the peer's next sends will start meeting ErrCreditExhausted. It is
// advisory for the peer's send-path consumers reading Throttle() outside this
// package; delivery does not depend on it, and credit alone keeps the queues
// bounded. One stream at its own credit stays below the threshold, since the
// peer's backpressure there is that stream's alone.
func (s *NoiseSession) signalReceiveOverload() {
	initial, _ := s.connWindow.ReceiveCeilings()
	if s.recvQueued.Load() < initial/4*3 {
		return
	}
	now := time.Now().UnixNano()
	last := s.lastOverloadSignal.Load()
	if now-last < int64(receiveOverloadInterval) || !s.lastOverloadSignal.CompareAndSwap(last, now) {
		return
	}
	_ = s.SendCongestion(aether.CongestionPayload{
		Reason:    aether.CongestionDownstream,
		Severity:  50,
		BackoffMs: uint16(receiveOverloadInterval / time.Millisecond),
	})
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
	// The streams still in s.streams keep their entries, so their credit goes
	// back to the peer's ledger here in one step, and a createStream racing
	// this close is refused by the closed ledger.
	s.admitted.close()
	s.leavePeerMemory(s.RemoteNodeID())
	if s.creditPeerShared {
		sessionPeerLedgers.leave(s.RemoteNodeID(), s.admitted.parent)
	}
	// Flush any pending conn-level grant so the peer gets credit for
	// bytes the application did consume, even if the session is
	// tearing down. Idempotent; safe even if never initialized.
	if s.connGrantDebouncer != nil {
		s.connGrantDebouncer.Close()
	}
	// Release any AcceptStreamByID waiters and drain the per-ID
	// backlog so blocked callers return ErrSessionClosed instead of
	// hanging. Backlog streams are reset because their recvQ /
	// reliability engine is otherwise orphaned — the acceptor
	// surfaces them and the adapter calls Reset because the
	// transport-specific teardown lives here.
	if s.acceptor != nil {
		for _, st := range s.acceptor.Close() {
			_ = st.Reset(aether.ResetCancel)
		}
	}
	// The session has ended for every caller (SignalClose above). A conn the
	// peer or the listener has closed already answers an error here that
	// leaves the caller nothing to do, so the close error is dropped and
	// CloseWithError answers nil for every session it ends.
	_ = s.conn.Close()
	return nil
}

// endWith closes the session for a cause found inside it: a stalled or idle
// peer, a failed write, a refused or timed-out preface, the read loop's end.
// CloseWithError answers nil for every session it ends, so there is no result
// for these callers to act on.
func (s *NoiseSession) endWith(cause error) {
	_ = s.CloseWithError(cause)
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

// sessionFrameKey is a session's per-frame AEAD key and the encryptor built on it,
// installed together by SetSessionKey so a reader that loads one sees the other.
type sessionFrameKey struct {
	enc *aethercrypto.FrameEncryptor
	key []byte
}

// SetSessionKey sets the per-frame encryption key and enables AEAD encryption.
// The key should be derived from the Noise handshake shared secret.
// When set, all outbound frames are encrypted and inbound frames are decrypted, and
// the session's decoder reads the encrypted short form 0x87, which it refuses before
// a key is set. It may be called on a running session (a mesh connection keys the
// session it has already started): the key and encryptor go in with one
// CompareAndSwap, which the frame paths' one Load each pairs with.
func (s *NoiseSession) SetSessionKey(key [32]byte) error {
	// Reject a second install so a key is never silently re-installed into
	// a fresh FrameEncryptor whose ordered nonce counter restarts at 0.
	// The encryptor's per-instance random nonce prefix already makes reinstall
	// nonce-safe, but a re-key mid-session is a caller bug (both directions
	// share the one encryptor); fail loud instead of masking it. The
	// CompareAndSwap makes this hold for two installs racing each other too.
	if s.frameKey.Load() != nil {
		return fmt.Errorf("aether: session key already set")
	}
	enc, err := aethercrypto.NewFrameEncryptor(key, true)
	if err != nil {
		return err
	}
	if !s.frameKey.CompareAndSwap(nil, &sessionFrameKey{enc: enc, key: append([]byte(nil), key[:]...)}) {
		return fmt.Errorf("aether: session key already set")
	}
	// The frame key is what authenticates a 0x87 frame's payload, so the decoder
	// reads that form from here on (processIncomingFrame decrypts it). The key is
	// stored first, so a decoder that reads the form finds the key in place.
	s.rxCompressor.AcceptEncryptedShort()
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

// SessionKey returns the per-frame key SetSessionKey installed, nil before it.
// handleHandshake reads it to check an address migration's HMAC.
func (s *NoiseSession) SessionKey() []byte {
	if fk := s.frameKey.Load(); fk != nil {
		return fk.key
	}
	return nil
}

func (s *NoiseSession) CongestionWindow() int64 { return s.congestion().CWND() }

// noiseConnStats is the optional observability surface exposed by the
// underlying *noiseConn. We probe via interface so `decryptErrors`,
// `inboxDrops`, rekey counters, and ECN CE-byte observations
// can flow through to SessionMetrics without the adapter needing a
// direct import of the noise/ package.
type noiseConnStats interface {
	DecryptErrors() uint64
	InboxDrops() uint64
	// Rekey telemetry: lifetime rekey count + bytes encrypted
	// since the last rekey. Pass-through to the embedded RekeyTracker
	// on the noiseConn (noise/rekey.go). A conn without these methods
	// misses the type assertion and the counters stay zero — graceful
	// degradation by design.
	RekeyTotal() uint64
	RekeyBytesSinceLast() uint64
	// AEAD-decrypt latency distribution: p50/p99 of the per-call
	// recv-side decrypt cost in microseconds. Sourced from the
	// noiseConn's decryptLatencyHist ring buffer (noise/session.go).
	// Bimodal p50/p99 split = CPU-saturated host queuing decrypt
	// goroutines; both tiers in µs = healthy. Zero when no samples yet.
	DecryptLatencySnapshot() (p50Us, p99Us uint64)
}

// noiseConnCE is the optional ECN hook exposed by *noiseConn — when the
// listener's ecnReader returns a CE-marked datagram, the conn adds the
// decrypted DATA packet's payload length (the frame bytes the peer wrote) to
// a CE-byte counter, and the adapter drains that counter on every outbound
// CompositeACK so the sender's OnCE handler reacts one RTT before queue
// overflow. Kept separate from
// noiseConnStats because ECN support is best-effort (not all kernels /
// build tags enable it); a conn without it leaves only the adapter's own
// ceObservedBytes, which RecordCEBytes fills for a consumer that observes
// CE above the conn.
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

// noiseConnWireVersions is the surface *noiseConn exposes for the wire
// version set its handshake chose (or its resume ticket recorded).
// NewNoiseSession lifts the set through it; the handshake has already
// refused a peer with no common required version, so a session never exists
// for one.
type noiseConnWireVersions interface {
	WireVersions() aether.NegotiatedWireVersions
}

// noiseConnRealm is the surface *noiseConn exposes for the mesh realm its
// handshake's Noise prologue bound it to, by the prologue's CRC32 fingerprint
// (a mesh session's network key, an over-conn session's grant realm), or false
// for a conn bound to none. NewNoiseSession reads it as the realm its fragment
// envelopes carry and check.
type noiseConnRealm interface {
	RealmID() (uint32, bool)
}

// fragmentBinding is what st stamps on the fragments of a message it splits.
func (s *NoiseSession) fragmentBinding(st *noiseStream) FragmentBinding {
	version, _ := s.wireVersions.Version(aether.WireVersionFragment)
	return FragmentBinding{
		Version:     version,
		Realm:       s.realmID,
		RealmBound:  s.realmBound,
		Peer:        s.LocalPeerID(),
		Incarnation: s.ConnectionID(),
		StreamID:    st.streamID,
		Generation:  st.generation,
	}
}

// WireVersions returns the wire version set the session's Noise handshake
// chose. The layer that owns an entry reads its version from it and refuses
// its own traffic when the entry is absent.
func (s *NoiseSession) WireVersions() aether.NegotiatedWireVersions {
	return s.wireVersions
}

var _ aether.WireVersionsReporter = (*NoiseSession)(nil)

func (s *NoiseSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	var suspiciousACKs, recvDrops, seqWraps, replayDup, replayAncient, fecEvictedLive uint64
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
		if st.fec != nil {
			fecEvictedLive += st.fec.EvictedCount()
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

	// The FEC eviction total: the streams still here, whichever level each runs,
	// and those that have gone. Each stream's decoder added its own count to
	// fecEvictedLeft when it released.
	fecEvicted := fecEvictedLive + s.fecEvictedLeft.Load()

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
		FECRecovered:       s.fecRecovered.Load(),
		StreamRefused:      s.StreamRefusedCount(),
		SeqNoWraps:         seqWraps,
		RecvWindowDrops:    recvDrops,
		DecryptErrors:      decryptErr,
		InboxDrops:         inboxDrops,
		// Anti-replay classification (Classify/Commit split). ReplayRejects
		// is the sum so a consumer that reads only the aggregate sees the
		// whole; the split surfaces the operational meaning. See
		// SessionMetrics docs for the distinction.
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
		HealthSRTTUs:  uint64(s.Health().SRTT().Microseconds()),
		PingsReceived: s.Health().PingsReceived(),

		// Observability histograms (write syscall, writeLoop park, cwnd
		// block, grant starve, cwnd util) and the TLP / RACK counters.
		// Percentile readouts are computed above; the int64
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

		// Noise send-cipher rekey telemetry. Sourced
		// from the RekeyTracker on the underlying *noiseConn via the
		// noiseConnStats interface probe above.
		RekeyTotal:          rekeyTotal,
		RekeyBytesSinceLast: rekeyBytesSinceLast,

		// Per-decrypt AEAD latency distribution. Sourced from
		// the decryptLatencyHist on the underlying *noiseConn via the
		// same noiseConnStats interface probe. Captures the bimodal
		// uncontended-vs-CPU-queued split that ordinary RTT histograms
		// hide. Zero on non-noise adapters (test loopback etc.).
		DecryptLatencyP50Us: decryptLatencyP50Us,
		DecryptLatencyP99Us: decryptLatencyP99Us,

		// Recv-window HOL-block percentiles. Populated by every
		// stream's RecvWindow when frames are flushed after waiting for
		// predecessors. Zero when no reordering has occurred this session.
		RecvWindowHOLP50Us: uint64(holP50),
		RecvWindowHOLP99Us: uint64(holP99),

		// Caller-block percentiles for Stream.Send. Populated by
		// noiseStream.Send via a defer that records (Send-return − Send-
		// entry). Distinct from WriteloopParkP*Us: this is the application-
		// facing block, that is the writeLoop's internal park. Samples
		// below streamSendBlockFloor (50µs) bypass the histogram and are
		// counted in StreamSendFastTotal so operators see both the tail
		// and the uncontended denominator.
		StreamSendBlockP50Us: uint64(streamSendBlockP50),
		StreamSendBlockP99Us: uint64(streamSendBlockP99),
		StreamSendFastTotal:  s.streamSendFastTotal.Load(),

		// Per-phase decomposition of StreamSendBlock. Recorded
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

		// Scheduler queue-depth percentiles. Sampled on every
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
// The three ack-validation guards (BaseACK-jump / oversize-range /
// invalid-bitmap in ProcessCompositeACK, and the CE-overclaim clamp in
// handleACK) trip as FALSE POSITIVES during the session warmup window: the
// send-window base is
// still settling and CE plausibility (Outstanding()) is small because the
// window is still filling, so a well-behaved peer's early ACKs read as
// suspicious. At weight 25 / threshold 100, four such trips inside the 60s
// warmup grace would GOAWAY-close a healthy noise-UDP session before it
// stabilises. Suppress ONLY ReasonACKValidation during
// warmup: the guard has already rejected/clamped the offending ACK (the
// CPU-exhaustion protection is in the guard, not in the score), so scoring it
// here only kills legitimate sessions. Every other reason (decrypt-fail,
// malformed-frame, replay, protocol-violation, flow-control) is an attack
// regardless of lifetime and still enforces immediately. A genuine crafted-ACK
// attacker is bounded to the warmup window (its ACKs are still rejected) and
// scores + closes the instant warmup ends.
//
// The guard covers BOTH ack-validation AND malformed-frame, and the false
// positive is NOT confined to warmup — an established session's recovery
// ACKs and large frames also trip the guard after warmup and would
// GOAWAY-close a healthy grade-A session. Since the guard already
// dropped/clamped the frame (CPU protection is in the guard, not the score),
// scoring→closing there is redundant and kills legitimate sessions. Three
// tiers for the two guard-covered reasons:
//
//	T1 warmup (< SessionWarmupGrace): SUPPRESS (no score).
//	T2 established grade-A (past warmup + actively app-DELIVERING,
//	   appBytesDelivered>0): FORENSIC-ONLY — record (forensicSuppressed) for
//	   triage visibility but do NOT score / close / arm the blacklist. A
//	   flooder never delivers app data (malformed fails Validate; bad-ACK is
//	   TypeACK, not handleData) so it can never reach T2. NOT blacklist-arming
//	   is deliberate: arming would relocate the reap-cycle to a
//	   reconnect-LOCKOUT — strictly worse.
//	T3 post-warmup zombie (past warmup + never app-delivered): FULL Report —
//	   a genuine slow-loris that only ever sends garbage still scores + closes
//	   + is blacklisted for the consumer's accept path.
//
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
		// Fall through to full Report (score + close + blacklist for the
		// consumer's accept path).
	}
	s.abuseTracker.Report(r)
}

// ForensicSuppressedCount returns the number of guard-covered abuse events
// (ack-validation / malformed-frame) that were RECORDED but deliberately not
// scored/closed on this established grade-A session (reportAbuse's
// forensic-only tier). Metrics() carries the same value
// (SessionMetrics.ForensicSuppressed); this accessor is for the consumer that
// sums a session's stats, with no caller in this repository outside its
// tests, so triage retains visibility into a genuine post-warmup attack that
// the forensic-only tier intentionally stops closing.
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
// applies a bounded grow/shrink based on SuggestedWindow, growth stopping at
// the stream's admitted credit (noiseStream.autoTune). Called from
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
		res := st.autoTune(rtt)
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
