/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	AcceptStream(ctx context.Context) (Stream, error)

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
	ReplayRejects uint64        // frames rejected by anti-replay window

	// Security observability counters. See _SECURITY.md for the attack
	// classes each addresses.
	SuspiciousACKs   uint64 // §3.2  — Composite ACKs rejected as malformed/oversized
	FECGroupsEvicted uint64 // §3.5  — FEC groups evicted by count/age pruning
	StreamRefused    uint64 // §3.12 — incoming stream opens rejected at cap
	SeqNoWraps       uint64 // §3.3  — SeqNo jumps rejected as wrap-attack
	RecvWindowDrops  uint64 //       — reorder-buffer overflow drops (total across streams)
	DecryptErrors    uint64 //       — decryption failures on incoming packets
	InboxDrops       uint64 //       — packets dropped because the session inbox was full

	// Per-stream observe metrics (ACK-observe mode — pure observation, no enforcement).
	// Available on all transport types. Keyed by stream ID.
	StreamObserve map[uint64]StreamObserveData `json:"streamObserve,omitempty"`
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
