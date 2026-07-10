//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package relay

import (
	"context"
	"net"
	"testing"

	aether "github.com/ORBTR/aether"
)

// fakeRelayConn is a no-op aether.Connection used to populate the external
// session table in AE-H-08 scope-roundtrip tests.
type fakeRelayConn struct {
	nodeID aether.NodeID
}

func (f *fakeRelayConn) Send(_ context.Context, _ []byte) error   { return nil }
func (f *fakeRelayConn) Receive(_ context.Context) ([]byte, error) { return nil, nil }
func (f *fakeRelayConn) Close() error                             { return nil }
func (f *fakeRelayConn) RemoteAddr() net.Addr                     { return nil }
func (f *fakeRelayConn) RemoteNodeID() aether.NodeID              { return f.nodeID }
func (f *fakeRelayConn) NetConn() net.Conn                        { return nil }
func (f *fakeRelayConn) Protocol() aether.Protocol                { return aether.Protocol(0) }
func (f *fakeRelayConn) OnClose(func())                           {}

func relayTestNodeID(name string) aether.NodeID {
	buf := make([]byte, RelayHeaderSize)
	copy(buf, name)
	return aether.NodeID(buf)
}

// TestRelayService_ExternalScope_Roundtrip verifies the AE-H-08 scope dimension
// added to the external session store: a bridge registered with a scope is
// returned by ExternalScope with that scope, and unregistering clears it.
func TestRelayService_ExternalScope_Roundtrip(t *testing.T) {
	rs := NewRelayService(RelayConfig{Enabled: true}, nil)
	id := relayTestNodeID("bridge")
	conn := &fakeRelayConn{nodeID: id}

	rs.RegisterExternal(id, conn, "scope-1")

	gotConn, gotScope, ok := rs.ExternalScope(id)
	if !ok {
		t.Fatal("ExternalScope: expected ok=true for registered bridge")
	}
	if gotConn != aether.Connection(conn) {
		t.Fatal("ExternalScope: returned connection does not match registered conn")
	}
	if gotScope != "scope-1" {
		t.Fatalf("ExternalScope: scope = %q, want scope-1", gotScope)
	}

	// LookupExternal still returns the bare connection (signature unchanged).
	if rs.LookupExternal(id) != aether.Connection(conn) {
		t.Fatal("LookupExternal: expected registered conn")
	}

	// Unknown id → not ok.
	if _, _, ok := rs.ExternalScope(relayTestNodeID("unknown")); ok {
		t.Fatal("ExternalScope: expected ok=false for unknown id")
	}

	// Unregister clears the entry.
	rs.UnregisterExternal(id)
	if _, _, ok := rs.ExternalScope(id); ok {
		t.Fatal("ExternalScope: expected ok=false after UnregisterExternal")
	}
}
