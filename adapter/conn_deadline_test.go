//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// creditlessStream is an aether.Stream whose Send blocks until its context
// ends, as a Noise stream's Send does when the peer grants no credit.
type creditlessStream struct{ sends chan struct{} }

func newCreditlessStream() *creditlessStream {
	return &creditlessStream{sends: make(chan struct{}, 16)}
}

func (s *creditlessStream) StreamID() uint64 { return 7 }
func (s *creditlessStream) Send(ctx context.Context, _ []byte) error {
	s.sends <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}
func (s *creditlessStream) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *creditlessStream) Close() error                   { return nil }
func (s *creditlessStream) Reset(aether.ResetReason) error { return nil }
func (s *creditlessStream) SetPriority(uint8, uint64)      {}
func (s *creditlessStream) Config() aether.StreamConfig    { return aether.StreamConfig{} }
func (s *creditlessStream) IsOpen() bool                   { return true }
func (s *creditlessStream) Conn() net.Conn                 { return NewStreamConn(s) }

// waitSend fails the test unless a Send has started within 2s.
func (s *creditlessStream) waitSend(t *testing.T, what string) {
	t.Helper()
	select {
	case <-s.sends:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not start within 2s", what)
	}
}

// writeResult is the outcome of one Write run by writeAsync.
type writeResult struct {
	n   int
	err error
	at  time.Time
}

func writeAsync(c net.Conn, p []byte) <-chan writeResult {
	out := make(chan writeResult, 1)
	go func() {
		n, err := c.Write(p)
		out <- writeResult{n, err, time.Now()}
	}()
	return out
}

func awaitWrite(t *testing.T, ch <-chan writeResult) writeResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("Write still blocked 3s after its deadline")
		return writeResult{}
	}
}

// A Write blocked in Send returns at its write deadline with
// os.ErrDeadlineExceeded and nothing written; a deadline already past
// refuses before Send; extending the deadline mid-Write extends that Write;
// clearing it lets a later Write block on credit again.
func TestStreamConn_BlockedWriteReturnsAtWriteDeadline(t *testing.T) {
	s := newCreditlessStream()
	c := NewStreamConn(s)

	deadline := time.Now().Add(100 * time.Millisecond)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	r := awaitWrite(t, writeAsync(c, []byte("blocked")))
	if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.n != 0 {
		t.Fatalf("blocked Write = (%d, %v), want (0, os.ErrDeadlineExceeded)", r.n, r.err)
	}
	if r.at.Before(deadline) {
		t.Fatalf("Write returned %v before its deadline", deadline.Sub(r.at))
	}
	s.waitSend(t, "the blocked Write's Send")

	// The deadline has passed: the next Write is refused without a Send.
	if n, err := c.Write([]byte("late")); !errors.Is(err, os.ErrDeadlineExceeded) || n != 0 {
		t.Fatalf("Write past the deadline = (%d, %v), want (0, os.ErrDeadlineExceeded)", n, err)
	}
	select {
	case <-s.sends:
		t.Fatal("Write past the deadline reached Send")
	default:
	}

	// Extending the deadline while a Write is blocked extends that Write.
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	pending := writeAsync(c, []byte("extended"))
	s.waitSend(t, "the Write's Send")
	extended := time.Now().Add(300 * time.Millisecond)
	if err := c.SetWriteDeadline(extended); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	r = awaitWrite(t, pending)
	if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.at.Before(extended) {
		t.Fatalf("extended Write returned (%v) %v before its extended deadline", r.err, extended.Sub(r.at))
	}

	// SetDeadline sets the write deadline too.
	if err := c.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := c.Write([]byte("past")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after a past SetDeadline: err = %v, want os.ErrDeadlineExceeded", err)
	}

	// Cleared: a Write blocks on credit with no bound.
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline(zero): %v", err)
	}
	cleared := writeAsync(c, []byte("unbounded"))
	s.waitSend(t, "the cleared Write's Send")
	select {
	case r := <-cleared:
		t.Fatalf("Write with no deadline returned (%d, %v) while Send was blocked", r.n, r.err)
	case <-time.After(150 * time.Millisecond):
	}
	_ = c.SetWriteDeadline(time.Now())
	awaitWrite(t, cleared)
}

// Each direction keeps its own deadline: a read deadline already past
// leaves a Write blocked, and a write deadline already past leaves a Read
// running to its own deadline.
func TestStreamConn_ReadAndWriteDeadlinesAreSeparate(t *testing.T) {
	s := newCreditlessStream()
	c := NewStreamConn(s)

	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	pending := writeAsync(c, []byte("x"))
	s.waitSend(t, "the Write's Send")
	select {
	case r := <-pending:
		t.Fatalf("a read deadline ended a Write: (%d, %v)", r.n, r.err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = c.SetWriteDeadline(time.Now())
	awaitWrite(t, pending)

	if err := c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	start := time.Now()
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read under a read deadline returned no error")
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("a past write deadline ended a Read early")
	}
}

// The gRPC adapter's conn wrapper hands deadlines to the connection it
// wraps: a Write blocked on a peer that does not read returns at its
// deadline. A wrapped connection with no deadline method makes the
// setters fail with os.ErrNoDeadline instead of reporting success.
func TestGrpcConnWrapper_BlockedWriteReturnsAtDeadline(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	w := &grpcConnWrapper{conn: local}

	deadline := time.Now().Add(100 * time.Millisecond)
	if err := w.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	r := awaitWrite(t, writeAsync(w, []byte("nobody reads this")))
	if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.at.Before(deadline) {
		t.Fatalf("blocked Write = (%d, %v), %v before its deadline", r.n, r.err, deadline.Sub(r.at))
	}

	if err := w.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := w.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked Read: err = %v, want os.ErrDeadlineExceeded", err)
	}

	plain := &grpcConnWrapper{conn: struct {
		io.Reader
		io.Writer
		io.Closer
	}{local, local, local}}
	for name, set := range map[string]func(time.Time) error{
		"SetDeadline":      plain.SetDeadline,
		"SetReadDeadline":  plain.SetReadDeadline,
		"SetWriteDeadline": plain.SetWriteDeadline,
	} {
		if err := set(time.Now()); !errors.Is(err, os.ErrNoDeadline) {
			t.Errorf("%s on a connection without deadlines: err = %v, want os.ErrNoDeadline", name, err)
		}
	}
}

// A Write on a QUIC stream's net.Conn view that the peer's flow control
// holds returns at its write deadline. The frame it cut short never
// reaches the peer as a message: the peer's Receive fails with the
// stream's reset, and a later Write on that stream fails at once.
func TestQuicStreamConn_BlockedWriteReturnsAtWriteDeadline(t *testing.T) {
	client, server := quicLoopback(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	c := st.Conn()

	deadline := time.Now().Add(200 * time.Millisecond)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	r := awaitWrite(t, writeAsync(c, make([]byte, 1<<20)))
	if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.n != 0 {
		t.Fatalf("blocked Write = (%d, %v), want (0, os.ErrDeadlineExceeded)", r.n, r.err)
	}
	if r.at.Before(deadline) {
		t.Fatalf("Write returned %v before its deadline", deadline.Sub(r.at))
	}

	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recvCancel()
	got, err := peer.Receive(recvCtx)
	var reset *quic.StreamError
	if !errors.As(err, &reset) {
		t.Fatalf("peer Receive = (%d bytes, %v), want the stream's reset", len(got), err)
	}

	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	start := time.Now()
	if _, err := c.Write([]byte("after")); err == nil {
		t.Fatal("Write on a stream whose frame was cut short succeeded")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Write on a reset stream took %v to fail", waited)
	}
}

// A Write on a GrpcStreamAdapter's net.Conn view whose send function
// blocks returns at its write deadline. The send function keeps its own
// copy of the message, and because that message may still be delivered,
// a later Write fails at once without calling the send function again. A
// Send whose context has already ended never calls it.
func TestGrpcStreamAdapterConn_BlockedWriteReturnsAtWriteDeadline(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var sent [][]byte
	send := func(p []byte) error {
		mu.Lock()
		sent = append(sent, p)
		mu.Unlock()
		<-release
		return nil
	}
	recv := func() ([]byte, error) { <-release; return nil, io.EOF }
	a := NewGrpcStreamAdapter(1, aether.StreamConfig{}, send, recv, nil)
	c := a.Conn()

	deadline := time.Now().Add(100 * time.Millisecond)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	msg := []byte("first")
	r := awaitWrite(t, writeAsync(c, msg))
	if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.n != 0 {
		t.Fatalf("blocked Write = (%d, %v), want (0, os.ErrDeadlineExceeded)", r.n, r.err)
	}
	if r.at.Before(deadline) {
		t.Fatalf("Write returned %v before its deadline", deadline.Sub(r.at))
	}
	copy(msg, "XXXXX")

	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	start := time.Now()
	if _, err := c.Write([]byte("second")); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after an abandoned send: err = %v, want the abandoned send's refusal", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Write after an abandoned send took %v to fail", waited)
	}
	close(release)
	mu.Lock()
	got := append([][]byte(nil), sent...)
	mu.Unlock()
	if len(got) != 1 || string(got[0]) != "first" {
		t.Fatalf("send function got %q, want one call with the Write's own bytes \"first\"", got)
	}

	// A Send whose context has already ended never calls the send function.
	// A Send that did call it would run it on its own goroutine, where a
	// failure could land after this test had returned, so the send function
	// only records its calls and the test goroutine reads the record. The
	// last Send has a context that cannot end, so it runs the send function
	// itself and first waits out any call an earlier Send left running. If
	// an earlier Send had started one and then returned on its ended
	// context, the adapter would refuse this Send as it refuses the Write
	// above. Without the refusal, Send picks between the ended context and
	// the send at random, so one Send would show it only some of the time;
	// 64 Sends leave a miss a 2^-64 chance.
	var freshCalls [][]byte
	fresh := NewGrpcStreamAdapter(2, aether.StreamConfig{},
		func(p []byte) error {
			mu.Lock()
			freshCalls = append(freshCalls, p)
			mu.Unlock()
			return nil
		}, recv, nil)
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 64; i++ {
		if err := fresh.Send(ended, []byte("x")); !errors.Is(err, context.Canceled) {
			t.Fatalf("Send %d with an ended context: err = %v, want context.Canceled", i, err)
		}
	}
	if err := fresh.Send(context.Background(), []byte("live")); err != nil {
		t.Fatalf("Send after 64 Sends with an ended context: %v, want nil: none of them may start the send function", err)
	}
	mu.Lock()
	got = append([][]byte(nil), freshCalls...)
	mu.Unlock()
	if len(got) != 1 || string(got[0]) != "live" {
		t.Fatalf("send function got %q, want one call, with \"live\": a Send with an ended context called it", got)
	}
}

// Close unblocks a Write blocked in Send, as net.Conn requires, whether or
// not a deadline is set, and a Write after Close is refused before Send.
// A deadline set after Close does not reopen the conn for Writes.
func TestStreamConn_CloseUnblocksBlockedWrite(t *testing.T) {
	for _, set := range []string{"no deadline", "SetDeadline", "SetWriteDeadline"} {
		s := newCreditlessStream()
		c := NewStreamConn(s)
		dl := time.Now().Add(5 * time.Second)
		switch set {
		case "SetDeadline":
			_ = c.SetDeadline(dl)
		case "SetWriteDeadline":
			_ = c.SetWriteDeadline(dl)
		}
		pending := writeAsync(c, []byte("blocked"))
		s.waitSend(t, set+": the Write's Send")
		closedAt := time.Now()
		if err := c.Close(); err != nil {
			t.Fatalf("%s: Close: %v", set, err)
		}
		select {
		case r := <-pending:
			if !errors.Is(r.err, net.ErrClosed) || r.n != 0 {
				t.Errorf("%s: Write blocked at Close = (%d, %v), want (0, net.ErrClosed)", set, r.n, r.err)
			}
			if waited := r.at.Sub(closedAt); waited > time.Second {
				t.Errorf("%s: Write returned %v after Close", set, waited)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: Write still blocked 2s after Close", set)
		}

		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		select {
		case r := <-writeAsync(c, []byte("late")):
			if !errors.Is(r.err, net.ErrClosed) || r.n != 0 {
				t.Errorf("%s: Write after Close = (%d, %v), want (0, net.ErrClosed)", set, r.n, r.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: Write after Close still blocked after 2s", set)
		}
		select {
		case <-s.sends:
			t.Errorf("%s: Write after Close reached Send", set)
		default:
		}
	}
}
