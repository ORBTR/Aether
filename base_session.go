/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"sync"
	"time"

	"github.com/ORBTR/aether/health"
)

// BaseSession holds the identity and lifecycle fields shared by every
// transport adapter (Noise, TCP, QUIC, …). Adapters embed *BaseSession
// so the standard accessor surface — LocalNodeID, RemoteNodeID,
// LocalPeerID, RemotePeerID, ConnectionID, Capabilities, Health,
// Protocol, IsClosed, LastActivity, IdleTimeout — lives in one place.
// Transport-specific state (writeMu, conn, reliability engines, etc.)
// stays on the adapter struct.
//
// The `closed` channel + closeOnce together implement the shared
// close-signal pattern: every adapter's CloseWithError calls
// SignalClose, which atomically transitions IsClosed to true and
// returns whether this was the first call. Adapters use that return
// value to decide whether to run their once-only teardown body.
//
// IdleTimeoutOverride / IdleTimeoutDefault: IdleTimeout() returns the
// override when > 0, else the default. Adapters that load the override
// from SessionOptions wire it once at construction; others can leave
// the override at zero to always return the default.
type BaseSession struct {
	localNodeID  NodeID
	remoteNodeID NodeID
	localPeerID  PeerID
	remotePeerID PeerID

	connID    ConnectionID
	proto     Protocol
	healthMon *health.Monitor

	closed    chan struct{}
	closeOnce sync.Once

	idleTimeoutOverride time.Duration
	idleTimeoutDefault  time.Duration
}

// NewBaseSession allocates and initialises a BaseSession bound to the
// supplied identities + protocol. Caller must set the health monitor +
// idle timeouts via the dedicated setters before going live —
// constructors carry their own initialisation order so we don't try to
// pack everything into one factory.
//
// proto identifies the underlying transport for Protocol() and
// CapabilitiesForProtocol lookups. localNodeID / remoteNodeID derive
// their PeerID forms via NodeID.ToPeerID — kept consistent across
// adapters.
func NewBaseSession(localNodeID, remoteNodeID NodeID, proto Protocol) *BaseSession {
	connID, _ := GenerateConnectionID()
	return &BaseSession{
		localNodeID:  localNodeID,
		remoteNodeID: remoteNodeID,
		localPeerID:  localNodeID.ToPeerID(),
		remotePeerID: remoteNodeID.ToPeerID(),
		connID:       connID,
		proto:        proto,
		closed:       make(chan struct{}),
	}
}

// SetHealthMonitor wires the session's health monitor. Must be called
// before any read/write loop starts — adapters typically do this
// immediately after NewBaseSession.
func (b *BaseSession) SetHealthMonitor(hm *health.Monitor) {
	b.healthMon = hm
}

// SetIdleTimeouts configures the IdleTimeout() return value. The
// override is honoured when > 0; otherwise the default is returned.
// Adapters wire the override from SessionOptions.SessionIdleTimeout and
// pass DefaultSessionIdleTimeout as the default.
func (b *BaseSession) SetIdleTimeouts(override, defaultTimeout time.Duration) {
	b.idleTimeoutOverride = override
	b.idleTimeoutDefault = defaultTimeout
}

// LocalNodeID returns the local peer's NodeID.
func (b *BaseSession) LocalNodeID() NodeID { return b.localNodeID }

// RemoteNodeID returns the remote peer's NodeID.
func (b *BaseSession) RemoteNodeID() NodeID { return b.remoteNodeID }

// LocalPeerID returns the 8-byte PeerID stamped into outbound frames'
// SenderID.
func (b *BaseSession) LocalPeerID() PeerID { return b.localPeerID }

// RemotePeerID returns the 8-byte PeerID stamped into outbound frames'
// ReceiverID.
func (b *BaseSession) RemotePeerID() PeerID { return b.remotePeerID }

// ConnectionID returns the per-session identifier minted at construction.
func (b *BaseSession) ConnectionID() ConnectionID { return b.connID }

// Protocol returns the transport label associated with this session.
func (b *BaseSession) Protocol() Protocol { return b.proto }

// Capabilities returns the protocol-derived capability set.
func (b *BaseSession) Capabilities() Capabilities { return CapabilitiesForProtocol(b.proto) }

// Health returns the session's health monitor — nil if SetHealthMonitor
// has not yet been called.
func (b *BaseSession) Health() *health.Monitor { return b.healthMon }

// IsClosed reports whether the session's close signal has fired.
func (b *BaseSession) IsClosed() bool {
	select {
	case <-b.closed:
		return true
	default:
		return false
	}
}

// CloseSignal returns the receive-only close channel for callers that
// need to select on it (writeLoop, ticker goroutines, helper closures).
func (b *BaseSession) CloseSignal() <-chan struct{} { return b.closed }

// SignalClose closes the shared close channel exactly once. Returns
// true when this call was the first to close the channel (i.e. the
// adapter should run its once-only teardown body); false on subsequent
// calls. Adapter CloseWithError methods rely on this to keep their
// teardown idempotent without each carrying their own sync.Once.
func (b *BaseSession) SignalClose() bool {
	first := false
	b.closeOnce.Do(func() {
		close(b.closed)
		first = true
	})
	return first
}

// LastActivity returns the session's health-monitor LastActivity
// timestamp. Satisfies the IdleEvictable interface so the connection
// manager can age out idle sessions.
func (b *BaseSession) LastActivity() time.Time {
	if b.healthMon == nil {
		return time.Time{}
	}
	return b.healthMon.LastActivity()
}

// IdleTimeout returns the configured idle eviction threshold — the
// SessionOptions override when set, else the default. Satisfies the
// IdleEvictable interface.
func (b *BaseSession) IdleTimeout() time.Duration {
	if b.idleTimeoutOverride > 0 {
		return b.idleTimeoutOverride
	}
	return b.idleTimeoutDefault
}
