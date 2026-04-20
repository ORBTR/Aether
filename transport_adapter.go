/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"context"
	"time"
)

// ProtocolAdapter is the pluggable interface for transport protocols.
// Each protocol (Noise, QUIC, WebSocket, gRPC) implements this.
// The TransportManager manages multiple adapters and selects the best one for each dial.
type ProtocolAdapter interface {
	// Protocol returns which protocol this adapter implements.
	Protocol() Protocol

	// Dial establishes a session to the target node.
	Dial(ctx context.Context, target Target) (Connection, error)

	// Listen starts accepting inbound sessions.
	Listen(ctx context.Context) (Listener, error)

	// Close shuts down the adapter and all its sessions.
	Close() error
}

// Pingable sends health probes and tracks ping/pong state.
// Implemented by transports that support protocol-level pings (Noise VL1 ping/pong).
// Consumers use type assertion on sessions.
type Pingable interface {
	// SendPing sends a health probe and returns the sequence number.
	SendPing() (uint32, error)

	// IncrementMissedPings increments the missed ping counter and returns the new count.
	IncrementMissedPings() int
}

// HealthReporter provides health metrics for a session.
// Implemented by any transport session that tracks connection quality.
// This is the primary interface for health monitoring — all session types
// that embed health.Monitor satisfy this automatically.
type HealthReporter interface {
	// LastActivity returns when the last packet was received.
	LastActivity() time.Time

	// RTT returns the last and exponential moving average round-trip time.
	RTT() (last, avg time.Duration)

	// IsAlive returns true if the session has received data within the timeout.
	IsAlive(timeout time.Duration) bool

	// MissedPings returns the count of consecutive missed pings.
	MissedPings() int

	// LastPongReceived returns when the last pong was received.
	LastPongReceived() time.Time

	// IsClosed returns true if the session has been closed.
	IsClosed() bool
}

// RelayCapable indicates a transport that can forward relay frames.
// Type-assert ProtocolAdapter to check support.
type RelayCapable interface {
	SupportsRelay() bool
	RegisterExternalSession(NodeID, Connection)
	UnregisterExternalSession(NodeID)
	HandleExternalRelayFrame(sourceNodeID NodeID, data []byte) error
}

// TicketCapable indicates a transport that supports session resumption.
type TicketCapable interface {
	IssueTicket(sess Connection) ([]byte, error)
	ResumeSession(ticket []byte) (Connection, error)
}

// AbuseReason is defined in the abuse/ subpackage as abuse.Reason. We
// can't import it here (would cause a cycle — abuse imports aether
// types via NodeID in its generic parameter). Callers that implement
// AbuseScoreCapable convert between abuse.Reason and this uint8 at the
// boundary. Reason codes must stay numerically stable across packages.
type AbuseReason uint8

// AbuseReason constants mirror abuse.Reason values. Keeping them
// duplicated here (with the same ordinal values) is the simplest way to
// avoid the import cycle without introducing a third package. The
// invariant is checked at compile time via the assertions in
// abuse/score.go.
const (
	AbuseReasonDecryptFail      AbuseReason = 0
	AbuseReasonMalformedFrame   AbuseReason = 1
	AbuseReasonACKValidation    AbuseReason = 2
	AbuseReasonStreamRefused    AbuseReason = 3
	AbuseReasonWHOISFlood       AbuseReason = 4
	AbuseReasonReplayDetected   AbuseReason = 5
	AbuseReasonProtocolViolation AbuseReason = 6
)

// AbuseScoreCapable indicates a session / adapter that supports
// per-peer behavioural scoring with a circuit-breaker. Every Aether
// adapter is a potential source of abuse events (malformed frames,
// stream-cap violations, replay attempts, ACK corruption) so this
// interface is session-agnostic — the concrete registry backing
// `abuse.Score[NodeID]` lives in the abuse/ subpackage but the surface
// exposed to consumers is uniform across transports.
//
// PeerAbuseScore returns the remote peer's current decayed score (0
// when no events recorded). SetAbuseScoreRegistry lets consumers share
// one registry across many sessions for cross-session dashboards. The
// concrete registry type is intentionally opaque (interface{}) here so
// this package doesn't import abuse; adapters type-assert at the
// implementation boundary.
type AbuseScoreCapable interface {
	// PeerAbuseScore returns the remote peer's current score.
	PeerAbuseScore() float64

	// SetAbuseScoreRegistry swaps the per-session registry for a shared
	// one. Argument must be *abuse.Score[aether.NodeID] in practice —
	// typed as `interface{}` here to avoid an import cycle. Returns
	// false if the registry type didn't match what the adapter expects.
	SetAbuseScoreRegistry(registry interface{}) bool
}

// IdleEvictable indicates a session that participates in automatic
// eviction after `SessionOptions.SessionIdleTimeout` of inactivity.
// Every long-lived Aether session should implement this — it lets
// consumers observe the eviction policy without depending on adapter-
// specific fields.
type IdleEvictable interface {
	// LastActivity returns when the session last received inbound data.
	LastActivity() time.Time

	// IdleTimeout returns the configured eviction threshold (0 =
	// disabled / use package default).
	IdleTimeout() time.Duration
}

// CompressionCapable indicates a session whose per-frame compression
// can be toggled at runtime. Useful for consumers that want to flip
// compression based on link type — e.g. disable on local WiFi where
// CPU savings matter more than bytes, enable on cellular / metered
// links where bytes matter more than CPU.
//
// Adapters where compression isn't applicable (byte-stream transports
// that rely on transport-native compression, or protocols with no
// per-frame DEFLATE layer) simply don't implement this. Consumers
// probe via type assertion.
type CompressionCapable interface {
	// CompressionEnabled returns the current toggle state.
	CompressionEnabled() bool

	// SetCompressionEnabled swaps the toggle atomically. Safe to call
	// under live traffic — in-flight frames complete with the policy
	// sampled at encode time; frames encoded after the setter returns
	// see the new policy.
	SetCompressionEnabled(bool)
}
