/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"io"
	"net"
	"time"
)

// NodeID identifies a node in the mesh.
type NodeID string

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Protocol — Transport Protocol Identifier
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Protocol identifies the transport protocol as a strongly-typed enum.
type Protocol uint8

const (
	ProtoUnknown   Protocol = 0
	ProtoNoise     Protocol = 1 // Noise-UDP: direct encrypted UDP
	ProtoQUIC      Protocol = 2 // QUIC: reliable UDP with multiplexing
	ProtoWebSocket Protocol = 3 // WebSocket: HTTP upgrade, proxy-compatible
	ProtoGRPC      Protocol = 4 // gRPC: HTTP/2 with native reliability and mux
	ProtoTCP       Protocol = 5 // TCP/TLS: reliable stream (used by the TCP adapter)
)

// Protocol name aliases.
const (
	ProtocolVL1  = ProtoNoise
	ProtocolQUIC = ProtoQUIC
	ProtocolWS   = ProtoWebSocket
	ProtocolGRPC = ProtoGRPC
	ProtocolTCP  = ProtoTCP
)

func (p Protocol) String() string {
	switch p {
	case ProtoNoise:
		return "noise"
	case ProtoQUIC:
		return "quic"
	case ProtoWebSocket:
		return "ws"
	case ProtoGRPC:
		return "grpc"
	case ProtoTCP:
		return "tcp"
	default:
		return "unknown"
	}
}

// ParseProtocol converts a string name to a Protocol enum value.
// Recognises both legacy names ("vl1") and new names ("noise").
func ParseProtocol(s string) Protocol {
	switch s {
	case "noise", "noise-udp", "vl1":
		return ProtoNoise
	case "quic":
		return ProtoQUIC
	case "ws", "websocket":
		return ProtoWebSocket
	case "grpc":
		return ProtoGRPC
	case "tcp", "tls":
		return ProtoTCP
	default:
		return ProtoUnknown
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Transport Capabilities
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// TransportCapabilities describes what a transport connection can do.
// Consumers derive their own quality models from these capabilities.
type TransportCapabilities struct {
	NativeReliability bool // TCP/QUIC/WS = true, raw UDP = false
	NativeOrdering    bool // TCP/QUIC = true, UDP = false
	NativeEncryption  bool // Noise/TLS/QUIC = true, plain = false
	NativeMux         bool // QUIC = true (native streams), others = false
	MaxMTU            int  // UDP = 1400, TCP = 65536, WS = 32768
	Bidirectional     bool // all current transports = true
	SupportsResume    bool // Noise (with tickets) = true
	SupportsMultipath bool // Multiple concurrent paths to same peer
}

// TransportCapabilitiesForProtocol returns the known capabilities for a protocol.
func TransportCapabilitiesForProtocol(proto Protocol) TransportCapabilities {
	switch proto {
	case ProtoNoise:
		return TransportCapabilities{
			NativeEncryption: true,
			MaxMTU:           1400,
			Bidirectional:    true,
			SupportsResume:   true,
		}
	case ProtoQUIC:
		return TransportCapabilities{
			NativeReliability: true,
			NativeOrdering:    true,
			NativeEncryption:  true,
			NativeMux:         true,
			MaxMTU:            65536,
			Bidirectional:     true,
		}
	case ProtoWebSocket:
		return TransportCapabilities{
			NativeReliability: true,
			NativeOrdering:    true,
			NativeEncryption:  true, // wss://
			MaxMTU:            32768,
			Bidirectional:     true,
		}
	case ProtoTCP:
		return TransportCapabilities{
			NativeReliability: true,
			NativeOrdering:    true,
			NativeEncryption:  true, // TLS
			MaxMTU:            65536,
			Bidirectional:     true,
		}
	case ProtoGRPC:
		return TransportCapabilities{
			NativeReliability: true,
			NativeOrdering:    true,
			NativeEncryption:  true,
			NativeMux:         true,
			MaxMTU:            65536,
			Bidirectional:     true,
		}
	default:
		return TransportCapabilities{Bidirectional: true}
	}
}

// Capabilities returns the transport capabilities for this protocol.
func (p Protocol) Capabilities() TransportCapabilities {
	return TransportCapabilitiesForProtocol(p)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Session Options
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// SessionOptions configures per-session feature flags. Passed when creating
// adapter sessions. Each session
// carries its own options, making Aether testable and multi-instance safe.
type SessionOptions struct {
	FEC            bool   // enable forward error correction (default: true for Noise)
	Compression    bool   // enable per-frame compression (default: true)
	Encryption     bool   // enable per-frame AEAD (default: true)
	Scheduler      bool   // enable WFQ priority scheduler (default: true)
	HeaderComp     bool   // enable short headers (default: true)
	FrameLogging   bool   // log every frame for debugging (default: false)
	MaxBandwidth   int64  // per-peer bytes/sec cap, 0 = unlimited
	CongestionAlgo string // "cubic" or "bbr" (default: "cubic")

	// MaxConcurrentStreams caps the number of streams the remote peer can
	// open against this session. Once reached, the adapter replies to
	// further OPEN frames with RESET(ResetRefused). Protects against
	// memory exhaustion from stream-flood attacks (_SECURITY.md §3.12 / S5).
	// 0 = use DefaultMaxConcurrentStreams.
	MaxConcurrentStreams int

	// MaxFECGroups caps the FEC decoder's in-flight group count. Older
	// groups are pruned from the decoder once this many are buffered.
	// Protects against unbounded memory growth from FEC_REPAIR flooding
	// with unique GroupIDs (_SECURITY.md §3.5 / S2).
	// 0 = use DefaultMaxFECGroups.
	MaxFECGroups int

	// SessionIdleTimeout is the deadline after which a session with no
	// inbound activity is reaped. Guards against resource leaks from
	// black-holed paths and slow-drip attackers that establish sessions
	// but never send data.
	// 0 = use DefaultSessionIdleTimeout.
	SessionIdleTimeout time.Duration
}

// DefaultMaxConcurrentStreams is the default per-session stream cap for
// Noise-UDP sessions. TCP/WS use a lower default in their own adapters.
const DefaultMaxConcurrentStreams = 1024

// DefaultMaxFECGroups is the default in-flight FEC decoder group budget.
const DefaultMaxFECGroups = 256

// DefaultSessionIdleTimeout is the deadline after which an inactive
// session is closed. Matches the default stream idle timeout but is
// enforced at the session level so the connection's goroutines are
// reclaimed, not just individual streams.
const DefaultSessionIdleTimeout = 5 * time.Minute

// DefaultSessionOptions returns production-safe defaults. Call this
// and then override individual fields to customise — e.g.
//
//	opts := aether.DefaultSessionOptions()
//	opts.FEC = false
//	opts.SessionIdleTimeout = 10 * time.Minute
//	sess := adapter.NewNoiseSession(conn, local, remote, opts)
//
// Adapters that accept SessionOptions normalize numeric zero-values via
// NormalizeSessionOptions — if you only need tweaks to numeric fields,
// a bare `SessionOptions{}` with your overrides also works, but bool
// defaults are NOT inferred (that would conflict with "explicit false
// to disable"). Start from DefaultSessionOptions() when in doubt.
func DefaultSessionOptions() SessionOptions {
	return SessionOptions{
		FEC:                  true,
		Compression:          true,
		Encryption:           true,
		Scheduler:            true,
		HeaderComp:           true,
		CongestionAlgo:       "cubic",
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
		MaxFECGroups:         DefaultMaxFECGroups,
	}
}

// NormalizeSessionOptions fills numeric / string zero-values with their
// documented defaults, returning a copy of opts. Boolean fields are
// passed through unchanged — Go's zero-value semantics can't distinguish
// "unset" from "explicitly false" for bools, so callers who want full
// defaults should start from DefaultSessionOptions().
//
// Fields normalised:
//
//   - MaxConcurrentStreams   : 0 → DefaultMaxConcurrentStreams
//   - MaxFECGroups           : 0 → DefaultMaxFECGroups
//   - SessionIdleTimeout     : 0 → DefaultSessionIdleTimeout
//   - CongestionAlgo         : "" → "cubic"
//
// Adapters call this at construction so a bare `SessionOptions{}` still
// gets sane caps + timeouts even when the caller doesn't care about
// those fields.
func NormalizeSessionOptions(opts SessionOptions) SessionOptions {
	if opts.MaxConcurrentStreams <= 0 {
		opts.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	if opts.MaxFECGroups <= 0 {
		opts.MaxFECGroups = DefaultMaxFECGroups
	}
	if opts.SessionIdleTimeout <= 0 {
		opts.SessionIdleTimeout = DefaultSessionIdleTimeout
	}
	if opts.CongestionAlgo == "" {
		opts.CongestionAlgo = "cubic"
	}
	return opts
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Session Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// IncomingSession represents a new incoming connection.
type IncomingSession struct {
	Session  Connection
	Reader   io.Reader
	Writer   io.Writer
	Metadata map[string]string // application-level metadata (e.g., "tenant_id")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STUN/NAT Types (NATType defined in frame.go as uint8 wire format)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// NATType constants are defined in frame.go as uint8 wire format.
// Use NATUnknown, NATOpen, NATFullCone, NATRestricted, NATPortRestricted,
// NATSymmetric, NATBlocked directly. String representation via NATType.String().

// ReflexiveAddress represents a public IP:port mapping discovered via STUN
type ReflexiveAddress struct {
	IP         net.IP        // Public IP visible to STUN server
	Port       int           // Public port visible to STUN server
	LocalAddr  *net.UDPAddr  // Local bind address used
	NATType    NATType       // Detected NAT type
	Discovered time.Time     // When this mapping was discovered
	TTL        time.Duration // How long this mapping is expected to be valid
}

// STUNConfig configures STUN NAT detection behavior
type STUNConfig struct {
	Enabled       bool          // Enable STUN NAT detection
	Servers       []string      // STUN server addresses (e.g., "stun.l.google.com:19302")
	Timeout       time.Duration // Timeout for STUN requests
	RetryInterval time.Duration // How often to retry failed STUN requests
	CacheTTL      time.Duration // How long to cache reflexive addresses
}

// DefaultSTUNConfig returns sensible defaults for STUN configuration
func DefaultSTUNConfig() STUNConfig {
	return STUNConfig{
		Enabled: true,
		Servers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun2.l.google.com:19302",
		},
		Timeout:       5 * time.Second,
		RetryInterval: 30 * time.Second,
		CacheTTL:      5 * time.Minute,
	}
}

// ScopeID scopes sessions to a namespace. Used for namespace isolation.
type ScopeID string
