//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"fmt"
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
	mu   sync.Mutex
	conn net.Conn // the Noise-encrypted connection (reads/writes encrypted UDP datagrams)

	localNodeID  aether.NodeID
	remoteNodeID aether.NodeID
	localPeerID  aether.PeerID
	remotePeerID aether.PeerID

	// Stream management
	streams  map[uint64]*noiseStream
	acceptCh chan *noiseStream

	// Stream layout — consumer-defined stream ID assignments
	layout aether.StreamLayout
	opts   aether.SessionOptions

	// Shared infrastructure
	writeMu    sync.Mutex
	healthMon  *health.Monitor
	sched      *scheduler.Scheduler
	connWindow *flow.ConnWindow
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
	//   FECReedSolomon → rsEncoder        / rsDecoder   (Concern #8)
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
	// rejected because the MaxConcurrentStreams cap is reached (S5).
	streamRefused uint64

	// ECN observation (#15). The receive path increments ceObservedBytes
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

	// Peer abuse scoring (S7 — _SECURITY.md §3.6/§3.9/§3.12). Session
	// tracks the remote peer's misbehaviour across subsystems (decrypt
	// errors, crafted ACKs, replay attempts, stream-cap violations, etc.)
	// and trips a circuit breaker when the score exceeds the threshold.
	// `reportAbuse` is the adapter-level hook wired into the counter
	// increment sites. Defaults to a per-session registry (1 entry); call
	// SetAbuseScoreRegistry to share one registry across many sessions so
	// operator dashboards can see a peer's cross-session behaviour in one
	// place.
	abuseScore *abuse.Score[aether.NodeID]

	// Stream GC — resets idle streams after timeout (exempts well-known 0-3)
	streamGC *aether.StreamGC

	// Stall detection — per-stream tracking for 2×SRTT no-progress probe
	lastBaseACK    map[uint64]uint32    // stream → last seen BaseACK
	lastProgressAt map[uint64]time.Time // stream → when BaseACK last advanced

	// FEC prune scheduling — rate-limit decoder GC to ~1/sec (S2).
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
	s := &NoiseSession{
		conn:               conn,
		localNodeID:        localNodeID,
		remoteNodeID:       remoteNodeID,
		localPeerID:        truncateID(localNodeID),
		remotePeerID:       truncateID(remoteNodeID),
		layout:             aether.DefaultStreamLayout(),
		opts:               opts,
		streams:            make(map[uint64]*noiseStream),
		acceptCh:           make(chan *noiseStream, 16),
		healthMon:          health.NewMonitor(0.2),
		sched:              scheduler.NewScheduler(),
		connWindow:         flow.NewConnWindow(0),
		pacer:              selectPacer(opts),
		fecEncoder:         reliability.NewFECEncoder(reliability.DefaultFECGroupSize),
		fecDecoder:         reliability.NewFECDecoder(),
		interleavedEncoder: reliability.NewInterleavedFECEncoder(reliability.DefaultFECGroupSize),
		interleavedDecoder: reliability.NewInterleavedFECDecoder(),
		compressor:         aether.NewCompressor(),
		tickStop:           make(chan struct{}),
		closed:             make(chan struct{}),
	}
	// Reed-Solomon encoder/decoder — instantiated even when no stream is
	// using FECReedSolomon, because the cost is just a small Galois-field
	// table. Streams opt in via StreamConfig.FECLevel = FECReedSolomon.
	s.rsEncoder, _ = reliability.NewRSEncoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)
	s.rsDecoder, _ = reliability.NewRSDecoder(reliability.DefaultRSDataShards, reliability.DefaultRSParityShards)

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
	s.abuseScore = abuse.New[aether.NodeID](abuse.DefaultConfig())

	s.lastBaseACK = make(map[uint64]uint32)
	s.lastProgressAt = make(map[uint64]time.Time)
	s.migrator = migration.NewMigrator()
	s.packetReplay = reliability.NewPacketReplayWindow()
	s.connID, _ = aether.GenerateConnectionID()
	s.classDefaults = aether.DefaultsForClass(aether.ClassRAW)
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(streamID uint64) {
		dbgNoise.Printf("StreamGC: resetting idle stream %d", streamID)
		s.mu.Lock()
		if st, ok := s.streams[streamID]; ok {
			st.Reset(aether.ResetTimeout)
			delete(s.streams, streamID)
		}
		s.mu.Unlock()
		s.sched.Unregister(streamID)
	})

	// PMTU prober sends PATH_PROBE frames to discover maximum segment size
	s.pmtuProber = pmtu.NewProber(func(probeID uint32, paddingSize uint16) error {
		payload := aether.EncodePathProbe(probeID, paddingSize)
		frame := &aether.Frame{
			SenderID:   s.localPeerID,
			ReceiverID: s.remotePeerID,
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
// burst-tolerant token-bucket is fine). Concern #14.
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
	case <-s.closed:
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
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
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

func (s *NoiseSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, fmt.Errorf("session closed")
	}
}

func (s *NoiseSession) LocalNodeID() aether.NodeID  { return s.localNodeID }
func (s *NoiseSession) RemoteNodeID() aether.NodeID { return s.remoteNodeID }
func (s *NoiseSession) LocalPeerID() aether.PeerID  { return s.localPeerID }
func (s *NoiseSession) RemotePeerID() aether.PeerID { return s.remotePeerID }

func (s *NoiseSession) Capabilities() aether.Capabilities {
	return aether.CapabilitiesForProtocol(aether.ProtoNoise)
}

func (s *NoiseSession) Ping(ctx context.Context) (time.Duration, error) {
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Keepalive,
		Type:       aether.TypePING,
		SeqNo:      uint32(time.Now().UnixNano() & 0xFFFFFFFF),
	}
	if err := s.writeFrame(frame); err != nil {
		return 0, err
	}
	_, avg := s.healthMon.RTT()
	return avg, nil
}

func (s *NoiseSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	payload := aether.EncodeGoAway(reason, message)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Control,
		Type:       aether.TypeGOAWAY,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	return s.writeFrame(frame)
}

func (s *NoiseSession) Close() error {
	return s.CloseWithError(nil)
}

func (s *NoiseSession) CloseWithError(err error) error {
	s.closeOnce.Do(func() {
		if err != nil {
			s.closeErr = err
		}
		close(s.closed)
		s.conn.Close()
	})
	return nil
}

func (s *NoiseSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
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
func (s *NoiseSession) ConnectionID() aether.ConnectionID { return s.connID }
func (s *NoiseSession) Health() *health.Monitor           { return s.healthMon }
func (s *NoiseSession) SessionKey() []byte                { return s.sessionKey }
func (s *NoiseSession) CongestionWindow() int64           { return s.congestion().CWND() }
func (s *NoiseSession) Protocol() aether.Protocol         { return aether.ProtoNoise }
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
	_, avg := s.healthMon.RTT()
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

// reportAbuse records a misbehaviour event against the remote peer. When
// the peer's running score crosses the threshold, the session is
// GOAWAYed with reason=Error and closed. See abuse/score.go for the
// decay/threshold model. Safe to call at high frequency — the registry
// uses exponential decay so transient events don't trip the breaker.
func (s *NoiseSession) reportAbuse(r abuse.Reason) {
	if s.abuseScore == nil {
		return
	}
	if _, exceeded := s.abuseScore.Record(s.remoteNodeID, r); exceeded {
		dbgNoise.Printf("peer %s blacklisted (abuse score exceeded): reason=%s", s.remoteNodeID.Short(), r)
		// GoAway + Close on the circuit-breaker edge. Best effort —
		// errors ignored because we're tearing down anyway.
		_ = s.GoAway(context.Background(), aether.GoAwayError, "abuse threshold")
		s.CloseWithError(fmt.Errorf("peer %s exceeded abuse threshold (reason: %s)", s.remoteNodeID.Short(), r))
	}
}

// PeerAbuseScore returns the remote peer's current score (exponentially
// decayed since last update). Useful for observability dashboards.
func (s *NoiseSession) PeerAbuseScore() float64 {
	if s.abuseScore == nil {
		return 0
	}
	return s.abuseScore.Current(s.remoteNodeID)
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
// adapter expects.
func (s *NoiseSession) SetAbuseScoreRegistry(r interface{}) bool {
	registry, ok := r.(*abuse.Score[aether.NodeID])
	if !ok {
		return false
	}
	s.abuseScore = registry
	return true
}

// LastActivity satisfies aether.IdleEvictable — returns when the
// session's healthMon last recorded inbound activity.
func (s *NoiseSession) LastActivity() time.Time {
	return s.healthMon.LastActivity()
}

// IdleTimeout satisfies aether.IdleEvictable — returns the effective
// idle eviction threshold (opts override, else package default).
func (s *NoiseSession) IdleTimeout() time.Duration {
	if s.opts.SessionIdleTimeout > 0 {
		return s.opts.SessionIdleTimeout
	}
	return aether.DefaultSessionIdleTimeout
}

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
	_, sessionAvgRTT := s.healthMon.RTT()

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
		if rtt <= 0 {
			continue
		}
		st.window.SetRTT(rtt)

		current := st.window.CurrentWindow()
		suggested := st.window.SuggestedWindow()
		if suggested == current {
			continue
		}
		delta := suggested - current
		maxStep := current / 4 // ±25 % per tick
		if delta > maxStep {
			delta = maxStep
		} else if delta < -maxStep {
			delta = -maxStep
		}
		if delta > 0 {
			if grown := st.window.GrowWindow(delta); grown > 0 {
				dbgNoise.Printf("autoTune stream=%d grow=%d current=%d rtt=%s",
					st.streamID, grown, current+grown, rtt)
			}
		} else if delta < 0 {
			if shrunk := st.window.ShrinkWindow(-delta); shrunk > 0 {
				dbgNoise.Printf("autoTune stream=%d shrink=%d current=%d rtt=%s",
					st.streamID, shrunk, current-shrunk, rtt)
			}
		}
		st.window.ResetPeak()
	}
}

// Compile-time interface check
var _ aether.Session = (*NoiseSession)(nil)
var _ aether.AbuseScoreCapable = (*NoiseSession)(nil)
var _ aether.IdleEvictable = (*NoiseSession)(nil)
var _ aether.CompressionCapable = (*NoiseSession)(nil)
