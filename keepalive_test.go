/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether_test

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/adapter"
)

// keepaliveRelay carries one TCP connection between a dialler and a listener over
// loopback and, once frozen, holds every byte it reads in either direction without
// closing anything: the shape of a peer whose machine vanished with no FIN.
type keepaliveRelay struct {
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func (r *keepaliveRelay) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		for r.frozen.Load() {
			time.Sleep(20 * time.Millisecond)
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *keepaliveRelay) close() {
	r.frozen.Store(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
}

// relayedTCPPair is a dialler session and a listener session over loopback TCP with the
// relay between them, both under opts.
func relayedTCPPair(t *testing.T, opts aether.SessionOptions) (dialler, listener aether.Session, relay *keepaliveRelay) {
	t.Helper()
	far, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = far.Close() })
	near, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = near.Close() })
	relay = &keepaliveRelay{}
	t.Cleanup(relay.close)

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := far.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	go func() {
		in, err := near.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", far.Addr().String())
		if err != nil {
			_ = in.Close()
			return
		}
		relay.mu.Lock()
		relay.conns = append(relay.conns, in, out)
		relay.mu.Unlock()
		go relay.pipe(out, in)
		go relay.pipe(in, out)
	}()
	dialConn, err := net.Dial("tcp", near.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	listenConn, ok := <-accepted
	if !ok {
		t.Fatal("the far side accepted nothing")
	}
	dialler, err = adapter.NewSessionForProtocol(dialConn, aether.ProtoTCP, "vl1_keepalive_dialler", "vl1_keepalive_listener", opts)
	if err != nil {
		t.Fatalf("dialler session: %v", err)
	}
	listener, err = adapter.NewSessionForProtocol(listenConn, aether.ProtoTCP, "vl1_keepalive_listener", "vl1_keepalive_dialler", opts)
	if err != nil {
		t.Fatalf("listener session: %v", err)
	}
	t.Cleanup(func() { _ = dialler.Close(); _ = listener.Close() })
	return dialler, listener, relay
}

// runKeepalive runs RunKeepalive on s until the test ends and reports its answer.
func runKeepalive(t *testing.T, s aether.Session) (<-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		done <- aether.RunKeepalive(ctx, s)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-returned:
		case <-time.After(30 * time.Second):
			t.Error("RunKeepalive did not return after its context ended")
		}
	})
	return done, cancel
}

// closeErr is the error an adapter session recorded at its close.
func closeErr(s aether.Session) error {
	if c, ok := s.(interface{ CloseErr() error }); ok {
		return c.CloseErr()
	}
	return nil
}

// idleHold is how long an idle session is watched under an idle eviction of
// idleTimeout: past three of the adapter's 10 s eviction ticks, each of which would reap
// a session nothing had been heard on for idleTimeout.
const (
	idleTimeout = 9 * time.Second
	idleHold    = 32 * time.Second
)

// TestAnIdleSessionUnderItsKeepaliveIsNeverEvicted: a session carrying no traffic, with
// a keepalive running on one side only, is never reaped by either side's idle eviction:
// each probe is an inbound frame on the far side and each answer one on the near side.
// The idle eviction here is shorter than the hold, so a session with no keepalive is
// reaped inside it.
func TestAnIdleSessionUnderItsKeepaliveIsNeverEvicted(t *testing.T) {
	opts := aether.DefaultSessionOptions()
	opts.SessionIdleTimeout = idleTimeout
	dialler, listener, _ := relayedTCPPair(t, opts)
	done, _ := runKeepalive(t, listener)

	deadline := time.Now().Add(idleHold)
	for time.Now().Before(deadline) {
		if dialler.IsClosed() || listener.IsClosed() {
			t.Fatalf("an idle session with its keepalive running was closed: dialler %v (%v), listener %v (%v)",
				dialler.IsClosed(), closeErr(dialler), listener.IsClosed(), closeErr(listener))
		}
		select {
		case err := <-done:
			t.Fatalf("RunKeepalive returned %v on a healthy session", err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// TestAnIdleSessionHeldTenMinutesIsNeverEvicted is the same hold at the default idle
// eviction for longer than ten minutes. It runs only with AETHER_KEEPALIVE_LONG=1.
func TestAnIdleSessionHeldTenMinutesIsNeverEvicted(t *testing.T) {
	if os.Getenv("AETHER_KEEPALIVE_LONG") != "1" {
		t.Skip("set AETHER_KEEPALIVE_LONG=1 to hold an idle session past ten minutes")
	}
	dialler, listener, _ := relayedTCPPair(t, aether.DefaultSessionOptions())
	done, _ := runKeepalive(t, listener)
	start := time.Now()
	for time.Since(start) < 10*time.Minute+30*time.Second {
		if dialler.IsClosed() || listener.IsClosed() {
			t.Fatalf("closed after %s: dialler %v, listener %v", time.Since(start).Round(time.Second), closeErr(dialler), closeErr(listener))
		}
		select {
		case err := <-done:
			t.Fatalf("RunKeepalive returned %v on a healthy session", err)
		case <-time.After(time.Second):
		}
	}
	t.Logf("held idle %s at SessionIdleTimeout %s; plan %+v", time.Since(start).Round(time.Second),
		aether.DefaultSessionIdleTimeout, aether.KeepalivePlanFor(listener))
}

// TestAFrozenPathEndsTheSessionWithinTheDeadPeerBound: once the path stops carrying
// bytes and nothing closes it, the keepalive ends the session with ErrKeepaliveDeadline
// within the plan's DeadPeerBound of the last frame heard, far inside the idle eviction.
func TestAFrozenPathEndsTheSessionWithinTheDeadPeerBound(t *testing.T) {
	_, listener, relay := relayedTCPPair(t, aether.DefaultSessionOptions())
	done, _ := runKeepalive(t, listener)

	// One answered probe first, so the freeze lands on a session the keepalive has
	// already found healthy; a keepalive that sends no probe is frozen after two of its
	// intervals, and the bound below is what finds it.
	warm := time.Now().Add(2 * aether.KeepalivePlanFor(listener).Interval)
	for listener.Health().SampleCount() < 1 && time.Now().Before(warm) {
		select {
		case err := <-done:
			t.Fatalf("RunKeepalive returned %v before its first probe was answered", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	relay.frozen.Store(true)
	plan := aether.KeepalivePlanFor(listener)
	lastHeard := listener.Health().LastActivity()

	bound := plan.DeadPeerBound()
	// The probes, their timeouts and the gaps between them are timers; one probe-poll
	// interval and scheduler latency on a loaded machine sit on top of them.
	const slack = 2 * time.Second
	select {
	case err := <-done:
		if !errors.Is(err, aether.ErrKeepaliveDeadline) {
			t.Fatalf("RunKeepalive = %v, want ErrKeepaliveDeadline", err)
		}
	case <-time.After(bound + slack - time.Since(lastHeard)):
		t.Fatalf("the session is still held %s after the last frame heard; the plan's bound is %s", time.Since(lastHeard).Round(time.Millisecond), bound)
	}
	released := time.Since(lastHeard)
	if !listener.IsClosed() {
		t.Fatal("RunKeepalive answered the deadline with the session still open")
	}
	if !errors.Is(closeErr(listener), aether.ErrKeepaliveDeadline) {
		t.Errorf("the session closed with %v, want ErrKeepaliveDeadline", closeErr(listener))
	}
	if released > bound+slack {
		t.Errorf("released %s after the last frame heard; the plan's bound is %s", released.Round(time.Millisecond), bound)
	}
	t.Logf("frozen path released %s after the last frame heard; plan %+v, DeadPeerBound %s", released.Round(time.Millisecond), plan, bound)
}

// TestTheKeepaliveEndsWithItsSessionOrItsContext: a keepalive on a session that closes,
// or whose context ends, returns nil and closes nothing it did not have to.
func TestTheKeepaliveEndsWithItsSessionOrItsContext(t *testing.T) {
	dialler, listener, _ := relayedTCPPair(t, aether.DefaultSessionOptions())
	done, cancel := runKeepalive(t, listener)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunKeepalive after its context ended = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunKeepalive did not return after its context ended")
	}
	if listener.IsClosed() || dialler.IsClosed() {
		t.Error("a keepalive whose context ended closed the session")
	}

	done, _ = runKeepalive(t, listener)
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunKeepalive after its session closed = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunKeepalive did not return after its session closed")
	}
}
