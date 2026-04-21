/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package relay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// fakeConn is a minimal aether.Connection for testing PairSessions. It
// routes Send payloads into an "outbound" channel and Receive from an
// "inbound" channel. Closing stops both.
type fakeConn struct {
	id        aether.NodeID
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeConn(id aether.NodeID) *fakeConn {
	return &fakeConn{
		id:       id,
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		closed:   make(chan struct{}),
	}
}

func (c *fakeConn) Send(ctx context.Context, payload []byte) error {
	select {
	case c.outbound <- append([]byte(nil), payload...):
		return nil
	case <-c.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *fakeConn) Receive(ctx context.Context) ([]byte, error) {
	select {
	case p, ok := <-c.inbound:
		if !ok {
			return nil, net.ErrClosed
		}
		return p, nil
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *fakeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *fakeConn) RemoteAddr() net.Addr        { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *fakeConn) RemoteNodeID() aether.NodeID { return c.id }
func (c *fakeConn) NetConn() net.Conn           { return nil }
func (c *fakeConn) Protocol() aether.Protocol   { return aether.ProtoNoise }
func (c *fakeConn) OnClose(fn func())           { /* no-op for tests */ }

// Happy path: PairSessions forwards from A's inbound → B's outbound and
// vice versa. (A's "inbound" represents what the peer sent TO A; B's
// "outbound" is what A relayed to B.)
func TestPairSessions_ForwardsBothDirections(t *testing.T) {
	a := newFakeConn("vl1_a")
	b := newFakeConn("vl1_b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- PairSessions(ctx, a, b, "test")
	}()

	// Peer sends to A → PairSessions reads via Receive(a) → relays via
	// Send(b) → appears in b.outbound.
	a.inbound <- []byte("from-a-peer")
	select {
	case got := <-b.outbound:
		if string(got) != "from-a-peer" {
			t.Errorf("a→b forward: got %q, want %q", got, "from-a-peer")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for a→b forward")
	}

	// Reverse direction.
	b.inbound <- []byte("from-b-peer")
	select {
	case got := <-a.outbound:
		if string(got) != "from-b-peer" {
			t.Errorf("b→a forward: got %q, want %q", got, "from-b-peer")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for b→a forward")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PairSessions didn't return after cancel")
	}
}

// Closing either side tears down both.
func TestPairSessions_CloseOneClosesBoth(t *testing.T) {
	a := newFakeConn("vl1_a")
	b := newFakeConn("vl1_b")

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- PairSessions(ctx, a, b, "close-test")
	}()

	// Close A. PairSessions must observe the error, cancel pump ctx,
	// and close B.
	_ = a.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PairSessions didn't return after closing A")
	}

	// B must also be closed.
	select {
	case <-b.closed:
	case <-time.After(100 * time.Millisecond):
		t.Error("PairSessions did not close B when A closed")
	}
}

// Nil connection is rejected.
func TestPairSessions_NilRejected(t *testing.T) {
	if err := PairSessions(context.Background(), nil, newFakeConn("x"), "nil-a"); err == nil {
		t.Error("expected error for nil a")
	}
	if err := PairSessions(context.Background(), newFakeConn("x"), nil, "nil-b"); err == nil {
		t.Error("expected error for nil b")
	}
}
