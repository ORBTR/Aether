/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package websocket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pongRelay carries one loopback TCP connection between two WSConns and, once frozen,
// holds every byte it reads in either direction without closing anything: a peer whose
// machine vanished with no FIN.
type pongRelay struct {
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func (r *pongRelay) pipe(dst, src net.Conn) {
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

func (r *pongRelay) close() {
	r.frozen.Store(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
}

// relayedConns is a pinging server WSConn and a client WSConn that only answers, over
// loopback TCP with the relay between them. Each side runs a read loop, as the session
// layer above a WSConn does; serverEnded receives the server loop's error and the time it
// ended.
func relayedConns(t *testing.T, pingInterval time.Duration) (server *WSConn, relay *pongRelay, serverEnded <-chan wsReadEnd) {
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
	relay = &pongRelay{}
	t.Cleanup(relay.close)
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
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := far.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	clientRaw, err := net.Dial("tcp", near.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	serverRaw, ok := <-accepted
	if !ok {
		t.Fatal("the far side accepted nothing")
	}
	server = NewWSConn(serverRaw, true, "client-peer", pingInterval)
	client := NewWSConn(clientRaw, false, "server-peer", 0)
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })

	ended := make(chan wsReadEnd, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				ended <- wsReadEnd{err: err, at: time.Now()}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	return server, relay, ended
}

type wsReadEnd struct {
	err error
	at  time.Time
}

// TestAWSConnHoldsItsPeerToThePongDeadline: a peer that answers every ping keeps the
// connection open past the deadline the keepalive plan derives from those answers; once
// the path stops carrying bytes, the connection closes within that plan's Silence of the
// first unanswered ping, and Read answers ErrPongDeadline.
func TestAWSConnHoldsItsPeerToThePongDeadline(t *testing.T) {
	const pingInterval = 100 * time.Millisecond
	server, relay, ended := relayedConns(t, pingInterval)

	// Enough answered pings for the plan to leave its warm-up floor, then a hold past
	// the plan's Silence with the peer still answering.
	for deadline := time.Now().Add(10 * time.Second); server.pongRTT.SampleCount() < 8; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d pong(s) in 10 s at a %s ping interval", server.pongRTT.SampleCount(), pingInterval)
		}
	}
	healthy := server.pongPlan().Silence() + 2*time.Second
	select {
	case e := <-ended:
		t.Fatalf("a peer answering every ping was closed: %v", e.err)
	case <-time.After(healthy):
	}

	relay.frozen.Store(true)
	frozenAt := time.Now()
	plan := server.pongPlan()
	// The first unanswered ping follows the freeze within one ping interval, and the
	// deadline is checked every RetryGap; scheduler latency on a loaded machine sits on
	// top of both.
	bound := pingInterval + plan.Silence() + plan.RetryGap + time.Second
	select {
	case e := <-ended:
		if !errors.Is(e.err, ErrPongDeadline) {
			t.Fatalf("Read ended with %v, want ErrPongDeadline", e.err)
		}
		released := e.at.Sub(frozenAt)
		if released > bound {
			t.Errorf("closed %s after the freeze; the bound is %s", released.Round(time.Millisecond), bound)
		}
		t.Logf("frozen peer closed %s after the freeze; plan %+v, Silence %s", released.Round(time.Millisecond), plan, plan.Silence())
	case <-time.After(bound + 5*time.Second):
		t.Fatalf("the connection is still open %s after the freeze; the bound is %s", time.Since(frozenAt).Round(time.Millisecond), bound)
	}
}
