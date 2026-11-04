//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// filledSender opens a stream on a session whose peer has stopped reading, and sends
// until a Send no longer returns inside its short context: the writeLoop is held in
// its write, so what Send took is what the scheduler holds. It returns the bytes
// accepted, within the stream credit.
func filledSender(t *testing.T, p *liteRawPeer, ctx context.Context, id uint64) (*tcpStream, int64) {
	t.Helper()
	st := p.open(ctx, id)
	msg := make([]byte, 128*1024)
	var taken int64
	for i := 0; ; i++ {
		short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		start := time.Now()
		err := st.Send(short, msg)
		cancel()
		if err != nil {
			if !errors.Is(err, flow.ErrCreditExhausted) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Send %d under a passed context: %v, want the backpressure and the context's error", i, err)
			}
			if took := time.Since(start); took >= flow.ConsumeTimeout {
				t.Fatalf("Send ran %s under a 300 ms context", took)
			}
			return st, taken
		}
		taken += messageCredit(int64(len(msg)))
		if i > 64 {
			t.Fatalf("%d bytes accepted against a conn that takes none", taken)
		}
	}
}

// TestTCPStream_SendWaitsAtTheStreamCredit: a conn that stops taking bytes stops Send
// at the bounds profile's stream credit: it waits under its context, then answers the
// typed backpressure, and nothing is lost. Once the conn takes bytes again the Send goes
// through and the peer reads every message accepted.
func TestTCPStream_SendWaitsAtTheStreamCredit(t *testing.T) {
	p := newLiteRawPeer(t)
	drainAtEnd(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, taken := filledSender(t, p, ctx, 60)
	credit := flow.CurrentBounds().StreamCredit
	if taken > credit || taken < credit/2 {
		t.Fatalf("Send took %d bytes against a conn that takes none, stream credit %d", taken, credit)
	}
	// As large as what was refused, so it needs the room the written frames give back.
	after := make([]byte, 128*1024)
	copy(after, "after")
	done := make(chan error, 1)
	go func() { done <- st.Send(ctx, after) }()
	var payloads int64
	for got := int64(0); ; {
		f := p.next()
		if f.Type != aether.TypeDATA {
			t.Fatalf("frame on the wire: %+v", f)
		}
		if bytes.HasPrefix(f.Payload, []byte("after")) {
			break
		}
		got += messageCredit(int64(len(f.Payload)))
		payloads = got
	}
	if payloads != taken {
		t.Fatalf("the peer read %d of the %d bytes Send accepted", payloads, taken)
	}
	if err := <-done; err != nil {
		t.Fatalf("Send once the conn took bytes: %v", err)
	}
}

// TestTCPStream_SendAnswersBackpressureAfterTheWait: a Send under a context with no
// deadline stops at flow.ConsumeTimeout with the typed backpressure, as a Noise Send
// does waiting for credit.
func TestTCPStream_SendAnswersBackpressureAfterTheWait(t *testing.T) {
	p := newLiteRawPeer(t)
	drainAtEnd(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, _ := filledSender(t, p, ctx, 62)
	start := time.Now()
	err := st.Send(context.Background(), make([]byte, 128*1024))
	if !errors.Is(err, flow.ErrCreditExhausted) {
		t.Fatalf("Send: %v, want flow.ErrCreditExhausted", err)
	}
	if took := time.Since(start); took < flow.ConsumeTimeout {
		t.Fatalf("Send gave up after %s, the wait is %s", took, flow.ConsumeTimeout)
	}
}

// TestTCPStream_AWaitingSendEndsWithItsStreamOrSession: a Send waiting for room reads
// the stream's typed end when the peer resets the stream, and the session's when it
// closes, without waiting out its time.
func TestTCPStream_AWaitingSendEndsWithItsStreamOrSession(t *testing.T) {
	big := make([]byte, 128*1024)
	t.Run("the peer's RESET", func(t *testing.T) {
		p := newLiteRawPeer(t)
		drainAtEnd(t, p)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		st, _ := filledSender(t, p, ctx, 64)
		done := make(chan error, 1)
		go func() { done <- st.Send(ctx, big) }()
		time.Sleep(50 * time.Millisecond)
		writeFrames(t, p.conn, &aether.Frame{StreamID: 64, Type: aether.TypeRESET, Payload: aether.EncodeReset(aether.ResetFlowCtrl)})
		select {
		case err := <-done:
			if !errors.Is(err, aether.ErrStreamOverrun) {
				t.Fatalf("Send on the peer's RESET: %v, want ErrStreamOverrun", err)
			}
		case <-time.After(flow.ConsumeTimeout / 2):
			t.Fatal("a waiting Send did not see the peer's RESET")
		}
	})
	t.Run("the peer's RESET with no queued frame to drop", func(t *testing.T) {
		p := newLiteRawPeer(t)
		drainAtEnd(t, p)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		st := p.open(ctx, 68)
		// One message that fills the room, which the writeLoop holds in its write; the
		// RESET drops nothing, so only the stream's end can wake the next Send.
		whole := make([]byte, flow.CurrentBounds().StreamCredit-recvQueueEntryCost)
		if err := st.Send(ctx, whole); err != nil {
			t.Fatalf("send: %v", err)
		}
		waitLong(t, "the writeLoop taking the frame", func() bool { return p.sess.sched.QueueLen(68) == 0 })
		done := make(chan error, 1)
		go func() { done <- st.Send(ctx, big) }()
		time.Sleep(50 * time.Millisecond)
		writeFrames(t, p.conn, &aether.Frame{StreamID: 68, Type: aether.TypeRESET, Payload: aether.EncodeReset(aether.ResetFlowCtrl)})
		select {
		case err := <-done:
			if !errors.Is(err, aether.ErrStreamOverrun) {
				t.Fatalf("Send on the peer's RESET: %v, want ErrStreamOverrun", err)
			}
		case <-time.After(flow.ConsumeTimeout / 2):
			t.Fatal("a waiting Send did not see the peer's RESET")
		}
	})
	t.Run("the session's close", func(t *testing.T) {
		p := newLiteRawPeer(t)
		drainAtEnd(t, p)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		st, _ := filledSender(t, p, ctx, 66)
		done := make(chan error, 1)
		go func() { done <- st.Send(ctx, big) }()
		time.Sleep(50 * time.Millisecond)
		go func() { _ = p.sess.Close() }()
		select {
		case err := <-done:
			if !errors.Is(err, aether.ErrSessionClosed) {
				t.Fatalf("Send on the session's close: %v, want ErrSessionClosed", err)
			}
		case <-time.After(flow.ConsumeTimeout / 2):
			t.Fatal("a waiting Send did not see the session's close")
		}
	})
}

// temporaryError is a net.Error that says to try again, as EAGAIN does.
type temporaryError struct{}

func (temporaryError) Error() string   { return "try again" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

// flakyConn takes part of a write and fails with err on every every-th write, and fails
// for good with fatal once failAfter writes have gone by.
type flakyConn struct {
	net.Conn
	every     int
	failAfter int
	fatal     error
	mu        sync.Mutex
	writes    int
}

func (c *flakyConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	n := c.writes
	c.mu.Unlock()
	if c.failAfter > 0 && n > c.failAfter {
		return 0, c.fatal
	}
	if c.every > 0 && n%c.every == 0 {
		part := len(b) / 2
		if part > 0 {
			if _, err := c.Conn.Write(b[:part]); err != nil {
				return 0, err
			}
		}
		return part, temporaryError{}
	}
	return c.Conn.Write(b)
}

// tcpOver builds two TCPSessions over a loopback connection, the client's writes going
// through wrap.
func tcpOver(t *testing.T, wrap func(net.Conn) net.Conn) (client, server *TCPSession) {
	t.Helper()
	c, s := loopbackPair(t)
	client = NewTCPSession(wrap(c), "vl1_flaky_client", "vl1_flaky_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server = NewTCPSession(s, "vl1_flaky_server", "vl1_flaky_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// TestTCPSession_ATemporaryWriteErrorLosesNoFrame: a conn that fails part way through
// every third write with a temporary error loses no frame and cuts no frame: every
// message arrives whole and in order, CLOSE included, and the session stays up.
func TestTCPSession_ATemporaryWriteErrorLosesNoFrame(t *testing.T) {
	client, server := tcpOver(t, func(c net.Conn) net.Conn { return &flakyConn{Conn: c, every: 3} })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 70, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const count = 200
	for i := 0; i < count; i++ {
		if err := st.Send(ctx, bytes.Repeat([]byte{byte(i)}, 1000+i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	for i := 0; i < count; i++ {
		got, err := acc.Receive(ctx)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if len(got) != 1000+i || got[0] != byte(i) || got[len(got)-1] != byte(i) {
			t.Fatalf("message %d: %d bytes, first %d", i, len(got), got[0])
		}
	}
	if _, err := acc.Receive(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("after the last message: %v, want the end the CLOSE gives", err)
	}
	if client.IsClosed() {
		t.Fatalf("the session closed: %v", client.CloseErr())
	}
}

// TestTCPSession_APermanentWriteErrorEndsTheSessionTyped: a write that fails with no
// retry ends the session at once, with the typed reason on the session and on its
// streams' Send and Receive, since the frame is lost and the framing may be cut.
func TestTCPSession_APermanentWriteErrorEndsTheSessionTyped(t *testing.T) {
	boom := fmt.Errorf("the conn broke")
	client, _ := tcpOver(t, func(c net.Conn) net.Conn {
		return &flakyConn{Conn: c, failAfter: 3, fatal: boom}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 72, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Send(ctx, []byte("lost")); err != nil && !errors.Is(err, aether.ErrSessionWriteFailed) {
		t.Fatalf("send: %v", err)
	}
	waitLong(t, "the session closing", func() bool { return client.IsClosed() })
	if err := client.CloseErr(); !errors.Is(err, aether.ErrSessionWriteFailed) || !errors.Is(err, boom) {
		t.Fatalf("close reason %v", err)
	}
	if err := st.Send(ctx, []byte("next")); !errors.Is(err, aether.ErrSessionWriteFailed) {
		t.Fatalf("Send after the failure: %v", err)
	}
	if _, err := st.Receive(ctx); !errors.Is(err, aether.ErrSessionWriteFailed) {
		t.Fatalf("Receive after the failure: %v", err)
	}
}

// TestSessionWriter_AClosedSessionStopsTheRetry: a conn that stays temporarily failed
// stops being retried when the session has closed, and the writer counts as failed.
func TestSessionWriter_AClosedSessionStopsTheRetry(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	closed := make(chan struct{})
	w := newSessionWriter(&flakyConn{Conn: c, failAfter: 0, every: 1}, closed)
	go func() { _, _ = io.Copy(io.Discard, s) }()
	close(closed)
	start := time.Now()
	if _, err := w.Write(make([]byte, 16)); err == nil || !w.failed() {
		t.Fatalf("Write on a closed session: %v, failed %v", err, w.failed())
	}
	if took := time.Since(start); took >= sessionWriteRetryWindow {
		t.Fatalf("the retry ran %s past the close", took)
	}
}
