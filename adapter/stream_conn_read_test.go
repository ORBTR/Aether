//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
	fnoise "github.com/flynn/noise"
)

// waitingStream is an aether.Stream with nothing from the peer: Receive
// reports each call on receives, then waits for a message on msgs or for
// its context to end. calls counts the Receives made.
type waitingStream struct {
	receives chan struct{}
	msgs     chan []byte
	mu       sync.Mutex
	calls    int
}

func newWaitingStream() *waitingStream {
	return &waitingStream{receives: make(chan struct{}, 16), msgs: make(chan []byte)}
}

func (s *waitingStream) Receive(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	s.receives <- struct{}{}
	select {
	case m := <-s.msgs:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *waitingStream) receiveCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// waitReceive fails the test unless a Receive has started within
// streamHangBound.
func (s *waitingStream) waitReceive(t *testing.T, what string) {
	t.Helper()
	select {
	case <-s.receives:
	case <-time.After(streamHangBound):
		t.Fatalf("%s: no Receive started within %v", what, streamHangBound)
	}
}

func (s *waitingStream) StreamID() uint64                   { return 9 }
func (s *waitingStream) Send(context.Context, []byte) error { return nil }
func (s *waitingStream) Close() error                       { return nil }
func (s *waitingStream) Reset(aether.ResetReason) error     { return nil }
func (s *waitingStream) SetPriority(uint8, uint64)          {}
func (s *waitingStream) Config() aether.StreamConfig        { return aether.StreamConfig{} }
func (s *waitingStream) IsOpen() bool                       { return true }
func (s *waitingStream) Conn() net.Conn                     { return NewStreamConn(s) }

// awaitDeadlineRead fails the test unless the Read behind ch returns
// nothing and an error that wraps os.ErrDeadlineExceeded and is a
// net.Error timeout, as net.Conn defines a Read past its deadline, no
// earlier than deadline and no later than readReturnBound after it.
func awaitDeadlineRead(t *testing.T, ch <-chan readResult, deadline time.Time, what string) {
	t.Helper()
	select {
	case r := <-ch:
		if len(r.data) != 0 || !errors.Is(r.err, os.ErrDeadlineExceeded) || !timedOut(r.err) {
			t.Fatalf("%s: Read = (%q, %v), want (nothing, os.ErrDeadlineExceeded as a net.Error timeout)", what, r.data, r.err)
		}
		if r.at.Before(deadline) {
			t.Fatalf("%s: Read returned %v before its deadline", what, deadline.Sub(r.at))
		}
	case <-time.After(time.Until(deadline) + readReturnBound):
		t.Fatalf("%s: Read still blocked %v after its deadline", what, readReturnBound)
	}
}

// awaitClosedRead fails the test unless the Read behind ch returns nothing
// and net.ErrClosed within readReturnBound.
func awaitClosedRead(t *testing.T, ch <-chan readResult, what string) {
	t.Helper()
	select {
	case r := <-ch:
		if len(r.data) != 0 || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("%s: Read = (%q, %v), want (nothing, net.ErrClosed)", what, r.data, r.err)
		}
	case <-time.After(readReturnBound):
		t.Fatalf("%s: Read still blocked %v after Close", what, readReturnBound)
	}
}

// stillBlocked fails the test if the Read behind ch returns within d.
func stillBlocked(t *testing.T, ch <-chan readResult, d time.Duration, what string) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("%s: Read returned (%q, %v), want it still waiting", what, r.data, r.err)
	case <-time.After(d):
	}
}

// A read deadline set, moved or cleared while a Read waits applies to
// that Read and does not end it early, as net.Conn requires: the one
// Receive the Read made is still the one running. Set while waiting, the
// deadline ends the Read at its time; moved later, the Read waits on and
// ends at the later time; cleared, the Read waits for its message. A Read
// that starts past its deadline returns at once without a Receive.
func TestStreamConn_ReadDeadlineChangedWhileReadWaits(t *testing.T) {
	s := newWaitingStream()
	c := NewStreamConn(s)

	pending := readAsync(c)
	s.waitReceive(t, "unbounded Read")
	deadline := time.Now().Add(100 * time.Millisecond)
	if err := c.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	awaitDeadlineRead(t, pending, deadline, "deadline set while the Read waited")

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	pending = readAsync(c)
	s.waitReceive(t, "Read under a 30s deadline")
	if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	stillBlocked(t, pending, 200*time.Millisecond, "deadline moved from 30s to 60s")
	deadline = time.Now().Add(100 * time.Millisecond)
	if err := c.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	awaitDeadlineRead(t, pending, deadline, "deadline moved in to 100ms by SetDeadline")
	if n := s.receiveCalls(); n != 2 {
		t.Fatalf("two Reads made %d Receives, want 2: moving a deadline ended a Read and a second Receive replaced it", n)
	}

	if err := c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	pending = readAsync(c)
	s.waitReceive(t, "Read under a 100ms deadline")
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(zero): %v", err)
	}
	stillBlocked(t, pending, 300*time.Millisecond, "deadline cleared")
	s.msgs <- []byte("late")
	awaitRead(t, pending, "late")

	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	before := s.receiveCalls()
	awaitDeadlineRead(t, readAsync(c), time.Now().Add(-time.Second), "Read past its deadline")
	if n := s.receiveCalls(); n != before {
		t.Fatalf("a Read past its deadline made a Receive")
	}
}

// SetReadDeadline and SetDeadline run beside a Read without racing it and
// without ending it: the race detector fails this test on a conn whose
// setters write what Read reads, and a Read the setters ended would fail
// here, since every deadline they set is an hour away.
func TestStreamConn_DeadlineSettersRunBesideRead(t *testing.T) {
	s := newWaitingStream()
	c := NewStreamConn(s)
	const rounds = 200
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < rounds; i++ {
			later := time.Now().Add(time.Hour)
			_ = c.SetReadDeadline(later)
			_ = c.SetDeadline(later)
		}
	}()
	go func() {
		for i := 0; i < rounds; i++ {
			s.msgs <- []byte("m")
		}
	}()
	buf := make([]byte, 8)
	for i := 0; i < rounds; i++ {
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "m" {
			t.Fatalf("Read %d beside the deadline setters = (%q, %v), want m", i, buf[:n], err)
		}
		<-s.receives
	}
	<-done
}

// Close ends a Read waiting in Receive, with or without a deadline, and
// that Read reports net.ErrClosed, as Write does. A Read after Close is
// refused before Receive, and a deadline set after Close does not reopen
// the conn for Reads.
func TestStreamConn_CloseUnblocksBlockedRead(t *testing.T) {
	for _, set := range []string{"no deadline", "SetDeadline", "SetReadDeadline"} {
		s := newWaitingStream()
		c := NewStreamConn(s)
		dl := time.Now().Add(time.Hour)
		switch set {
		case "SetDeadline":
			_ = c.SetDeadline(dl)
		case "SetReadDeadline":
			_ = c.SetReadDeadline(dl)
		}
		pending := readAsync(c)
		s.waitReceive(t, set)
		if err := c.Close(); err != nil {
			t.Fatalf("%s: Close: %v", set, err)
		}
		awaitClosedRead(t, pending, set+": Read waiting at Close")

		_ = c.SetReadDeadline(time.Now().Add(time.Hour))
		before := s.receiveCalls()
		awaitClosedRead(t, readAsync(c), set+": Read after Close")
		if n := s.receiveCalls(); n != before {
			t.Errorf("%s: a Read after Close made a Receive", set)
		}
	}
}

// The rest of a message a Read returned in part comes back from the next
// Read without waiting, even past the read deadline, since that message
// has already left the stream; never after Close. A deadline setter drops
// it: the next Read waits for the next message.
func TestStreamConn_ReadBufferedRest(t *testing.T) {
	s := newWaitingStream()
	c := NewStreamConn(s)
	half := make([]byte, 3)

	deadline := time.Now().Add(100 * time.Millisecond)
	_ = c.SetReadDeadline(deadline)
	go func() { s.msgs <- []byte("abcdef") }()
	if n, err := c.Read(half); err != nil || string(half[:n]) != "abc" {
		t.Fatalf("first Read = (%q, %v), want abc", half[:n], err)
	}
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	if n, err := c.Read(half); err != nil || string(half[:n]) != "def" {
		t.Fatalf("Read of the rest past the deadline = (%q, %v), want def", half[:n], err)
	}

	_ = c.SetReadDeadline(time.Time{})
	go func() { s.msgs <- []byte("ghijkl") }()
	if n, err := c.Read(half); err != nil || string(half[:n]) != "ghi" {
		t.Fatalf("Read = (%q, %v), want ghi", half[:n], err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Hour))
	go func() { s.msgs <- []byte("next") }()
	awaitRead(t, readAsync(c), "next")

	go func() { s.msgs <- []byte("mnopqr") }()
	if n, err := c.Read(half); err != nil || string(half[:n]) != "mno" {
		t.Fatalf("Read = (%q, %v), want mno", half[:n], err)
	}
	_ = c.Close()
	if n, err := c.Read(half); !errors.Is(err, net.ErrClosed) || n != 0 {
		t.Fatalf("Read of the rest after Close = (%q, %v), want (nothing, net.ErrClosed)", half[:n], err)
	}
}

// readView opens one stream on a real adapter whose peer sends nothing
// and returns the stream's net.Conn view.
type readView struct {
	name string
	open func(t *testing.T, id uint64) net.Conn
}

// noisePipeSession runs a Noise handshake over net.Pipe through
// DialSessionOverConn and AcceptSessionOverConn and returns the dialed
// session; both close with the test.
func noisePipeSession(t *testing.T) *NoiseSession {
	t.Helper()
	keypair := func() fnoise.DHKey {
		kp, err := fnoise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		return kp
	}
	a, b := keypair(), keypair()
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	accepted := make(chan *NoiseSession, 1)
	go func() {
		s, err := AcceptSessionOverConn(ctx, noise.AcceptConnConfig{
			LocalNodeID: "vl1_read-view-server", StaticPriv: b.Private, StaticPub: b.Public,
		}, serverConn, aether.DefaultSessionOptions())
		if err != nil {
			t.Errorf("AcceptSessionOverConn: %v", err)
		}
		accepted <- s
	}()
	client, err := DialSessionOverConn(ctx, noise.DialConnConfig{
		LocalNodeID: "vl1_read-view-client", StaticPriv: a.Private, StaticPub: a.Public,
	}, clientConn, aether.DefaultSessionOptions())
	if err != nil {
		t.Fatalf("DialSessionOverConn: %v", err)
	}
	server := <-accepted
	t.Cleanup(func() {
		_ = client.Close()
		if server != nil {
			_ = server.Close()
		}
	})
	return client
}

func openOn(t *testing.T, sess aether.Session, id uint64) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	st, err := sess.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	return st.Conn()
}

func readViews() []readView {
	return []readView{
		{"noise", func(t *testing.T, id uint64) net.Conn { return openOn(t, noisePipeSession(t), id) }},
		{"tcp", func(t *testing.T, id uint64) net.Conn {
			client, _, cleanup := aer099NewPair(t)
			t.Cleanup(cleanup)
			return openOn(t, client, id)
		}},
		{"quic", func(t *testing.T, id uint64) net.Conn {
			client, _ := quicLoopback(t)
			return openOn(t, client, id)
		}},
		{"grpc", func(t *testing.T, id uint64) net.Conn {
			never := make(chan struct{})
			t.Cleanup(func() { close(never) })
			recv := func() ([]byte, error) { <-never; return nil, io.EOF }
			return NewGrpcStreamAdapter(id, aether.StreamConfig{}, func([]byte) error { return nil }, recv, nil).Conn()
		}},
	}
}

// readSettle is how long a test lets a Read it started reach the
// adapter's Receive before it acts on the Read. A Read that has not got
// there yet still meets the deadline or the Close the test then makes,
// and returns the same, so the wait only makes the waiting case the
// usual one.
const readSettle = 50 * time.Millisecond

// On every adapter's net.Conn view, with the peer sending nothing, a read
// deadline set while a Read waits ends that Read at its time with
// os.ErrDeadlineExceeded as a net.Error timeout, and Close ends a waiting
// Read, with or without a deadline, with net.ErrClosed.
func TestStreamConn_ReadDeadlineAndCloseOnEveryAdapter(t *testing.T) {
	for _, v := range readViews() {
		t.Run(v.name, func(t *testing.T) {
			c := v.open(t, 11)
			pending := readAsync(c)
			time.Sleep(readSettle)
			deadline := time.Now().Add(100 * time.Millisecond)
			if err := c.SetReadDeadline(deadline); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			awaitDeadlineRead(t, pending, deadline, "deadline set while the Read waited")

			if err := c.SetReadDeadline(time.Time{}); err != nil {
				t.Fatalf("SetReadDeadline(zero): %v", err)
			}
			pending = readAsync(c)
			time.Sleep(readSettle)
			if err := c.Close(); err != nil {
				t.Logf("Close: %v", err)
			}
			awaitClosedRead(t, pending, "Read with no deadline waiting at Close")

			far := v.open(t, 12)
			if err := far.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			pending = readAsync(far)
			time.Sleep(readSettle)
			if err := far.Close(); err != nil {
				t.Logf("Close: %v", err)
			}
			awaitClosedRead(t, pending, "Read under a far deadline waiting at Close")
		})
	}
}
