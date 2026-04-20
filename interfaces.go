/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"context"
	"net"
)

// Transport is the common interface for all wire protocols.
type Transport interface {
	// Dial establishes a session to a remote node.
	Dial(ctx context.Context, target Target) (Connection, error)

	// Listen starts accepting incoming sessions.
	Listen(ctx context.Context) (Listener, error)

	// Close shuts down the transport.
	Close() error
}

// Connection represents an active raw transport connection to a peer.
// Established by transport-specific handshakes (Noise, TLS, QUIC).
// One Connection carries one Session after Aether negotiation.
type Connection interface {
	// Send transmits a payload.
	Send(ctx context.Context, payload []byte) error

	// Receive waits for a payload.
	Receive(ctx context.Context) ([]byte, error)

	// Close terminates the connection.
	Close() error

	// RemoteAddr returns the remote address.
	RemoteAddr() net.Addr

	// RemoteNodeID returns the ID of the connected peer.
	RemoteNodeID() NodeID

	// NetConn returns the underlying net.Conn for transport-level operations
	// (Aether negotiation, address extraction, TLS inspection).
	NetConn() net.Conn

	// Protocol returns which transport protocol this connection uses.
	Protocol() Protocol

	// OnClose registers a callback invoked when the connection closes.
	OnClose(fn func())
}

// Listener accepts incoming sessions.
type Listener interface {
	// Accept waits for the next incoming session.
	Accept(ctx context.Context) (Connection, error)

	// Close stops listening.
	Close() error

	// Addr returns the local address.
	Addr() net.Addr
}

// Target represents a destination for Dial.
type Target struct {
	NodeID   NodeID
	Address  string
	Protocol Protocol
	// Metadata allows passing transport-specific options
	Metadata map[string]string
}

// ConnProvider is implemented by sessions that can expose their underlying net.Conn.
// Used for protocol-agnostic mux negotiation — replaces *BaseConnection type assertions.
// Any session type that wraps a net.Conn should implement this interface.
type ConnProvider interface {
	NetConn() net.Conn
}

// TenantAwareSession is implemented by sessions that carry a scope identifier.
// SharedTransport preamble sessions and TenantSession wrappers implement this.
// Callers can type-assert incoming sessions to extract the transport-level scope.
type TenantAwareSession interface {
	ScopeID() string
}

// BindAddressResolver resolves the correct bind address for a given port.
// Implementations handle platform-specific requirements (e.g., Fly.io's
// fly-global-services for UDP). The mesh package stays platform-agnostic.
type BindAddressResolver interface {
	ResolveUDPBind(port int) string // returns primary "host:port" or ":port"
	// ResolveUDPBindDualStack returns separate IPv4 and IPv6 bind addresses.
	// Returns ("", "") if dual-stack isn't needed (single bind is sufficient).
	// When both are non-empty, the transport opens two listeners.
	ResolveUDPBindDualStack(port int) (ipv4Addr, ipv6Addr string)

	// OpenUDPListener creates a UDP socket bound to the platform-appropriate address.
	// Platforms that need special bind semantics (e.g., eBPF-intercepted hostnames)
	// override the default net.ResolveUDPAddr + net.ListenUDP behavior here.
	// The transport calls this instead of opening sockets directly.
	OpenUDPListener(network, address string) (*net.UDPConn, error)
}
