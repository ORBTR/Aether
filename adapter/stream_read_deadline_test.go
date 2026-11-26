//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// readReturnBound is how long after its read deadline a Read may still be
// blocked before a test calls it stuck. A Read that honours its deadline
// returns within a scheduler wake-up of it, so a passing run never comes
// near the bound. It is also well under QUIC's 30s idle timeout, so a Read
// that ignores its deadline cannot return by that route first and be
// taken for one that honoured it.
const readReturnBound = 10 * time.Second

// readResult is the outcome of one Read run by readAsync.
type readResult struct {
	data []byte
	err  error
	at   time.Time
}

func readAsync(c net.Conn) <-chan readResult {
	out := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		out <- readResult{buf[:n], err, time.Now()}
	}()
	return out
}

// timedOut reports whether err is a net.Error whose Timeout is true, as
// what a Read past its deadline returns is. The os.ErrDeadlineExceeded
// that StreamConn.Read returns is one; the tests in stream_conn_read_test.go
// ask for that error by name.
func timedOut(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

// awaitTimedOutRead fails the test unless the Read behind ch returns
// nothing and a timeout, no earlier than deadline and no later than
// readReturnBound after it.
func awaitTimedOutRead(t *testing.T, ch <-chan readResult, deadline time.Time) {
	t.Helper()
	select {
	case r := <-ch:
		if !timedOut(r.err) || len(r.data) != 0 {
			t.Fatalf("blocked Read = (%q, %v), want (nothing, a timeout)", r.data, r.err)
		}
		if r.at.Before(deadline) {
			t.Fatalf("Read returned %v before its deadline", deadline.Sub(r.at))
		}
	case <-time.After(time.Until(deadline) + readReturnBound):
		t.Fatalf("Read still blocked %v after its deadline", readReturnBound)
	}
}

// awaitRead fails the test unless the Read behind ch returns want within
// streamHangBound.
func awaitRead(t *testing.T, ch <-chan readResult, want string) {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil || string(r.data) != want {
			t.Fatalf("Read = (%q, %v), want %q", r.data, r.err, want)
		}
	case <-time.After(streamHangBound):
		t.Fatalf("Read of %q did not return within %v", want, streamHangBound)
	}
}

// A Read on a QUIC stream's net.Conn view that has nothing to read
// returns at its read deadline, and the stream stays usable: a frame the
// peer sends afterwards is what a later Read returns.
func TestQuicStreamConn_BlockedReadReturnsAtReadDeadline(t *testing.T) {
	client, server := quicLoopback(t)
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := st.Send(ctx, []byte("first")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	c := peer.Conn()
	awaitRead(t, readAsync(c), "first")

	deadline := time.Now().Add(200 * time.Millisecond)
	if err := c.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	awaitTimedOutRead(t, readAsync(c), deadline)

	if err := c.SetReadDeadline(time.Now().Add(streamHangBound)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := st.Send(ctx, []byte("second")); err != nil {
		t.Fatalf("Send after the peer's Read timed out: %v", err)
	}
	awaitRead(t, readAsync(c), "second")
}

// fedStream is a quic.Stream whose Read returns the bytes a test feeds it
// and waits when it has none, or returns io.EOF once the test has ended
// it. Like quic-go's stream, a Read fails with a timeout once a non-zero
// read deadline has passed, and SetReadDeadline wakes a waiting Read to
// look again. Each Read that starts to wait sends on waits, so a test can
// tell that everything fed has been read.
type fedStream struct {
	fakeAEH01Stream
	waits    chan struct{}
	mu       sync.Mutex
	changed  *sync.Cond
	data     []byte
	ended    bool
	deadline time.Time
}

func newFedStream() *fedStream {
	s := &fedStream{waits: make(chan struct{}, 16)}
	s.changed = sync.NewCond(&s.mu)
	return s
}

func (s *fedStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
			return 0, fakeTimeout{}
		}
		if len(s.data) > 0 {
			n := copy(p, s.data)
			s.data = s.data[n:]
			return n, nil
		}
		if s.ended {
			return 0, io.EOF
		}
		s.waits <- struct{}{}
		s.changed.Wait()
	}
}

func (s *fedStream) feed(b []byte) {
	s.mu.Lock()
	s.data = append(s.data, b...)
	s.mu.Unlock()
	s.changed.Broadcast()
}

// end makes Read return io.EOF once the bytes already fed are read.
func (s *fedStream) end() {
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
	s.changed.Broadcast()
}

func (s *fedStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	s.changed.Broadcast()
	return nil
}

func (s *fedStream) readDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// quicFrame is data as quicStream.Send frames it: a 4-byte length, then
// the bytes.
func quicFrame(data string) []byte {
	f := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(f, uint32(len(data)))
	return append(f, data...)
}

// A Receive that its context ends partway through a frame keeps the part
// it read: the stream stays in the session, the QUIC read deadline it
// moved is cleared, and the next Receive goes on from that part, so the
// frame comes out whole however many Receives it took. The test cuts one
// frame inside its length and again inside its payload. A Receive whose
// context has already ended reads nothing: the frame waiting for it is
// still there for the next one, and 32 tries leave a Receive that only
// sometimes read it almost no chance of passing.
func TestQuicStream_ReceiveResumesAFrameItsContextCutShort(t *testing.T) {
	fake := newFedStream()
	sess := newAEH01Session(t)
	st := registerAEH01Stream(sess, 1, fake)
	frame := quicFrame("hello world")

	// cut feeds part and runs a Receive that must wait for more, then ends
	// its context once the Receive has read all of part.
	cut := func(part []byte, where string) {
		t.Helper()
		fake.feed(part)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		got := make(chan error, 1)
		go func() {
			_, err := st.Receive(ctx)
			got <- err
		}()
		select {
		case <-fake.waits:
		case <-time.After(streamHangBound):
			t.Fatalf("%s: Receive did not read the part of the frame fed to it", where)
		}
		cancel()
		select {
		case err := <-got:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: Receive = %v, want context.Canceled", where, err)
			}
		case <-time.After(readReturnBound):
			t.Fatalf("%s: Receive still blocked %v after its context ended", where, readReturnBound)
		}
		if n := mapLen(sess); n != 1 {
			t.Fatalf("%s: the session holds %d streams after the Receive, want 1: its context ending is not the stream's end", where, n)
		}
		if dl := fake.readDeadline(); !dl.IsZero() {
			t.Fatalf("%s: read deadline after the Receive = %v, want none", where, dl)
		}
	}
	cut(frame[:2], "inside the length")
	cut(frame[2:9], "inside the payload")

	fake.feed(frame[9:])
	fake.feed(quicFrame("next"))
	for _, want := range []string{"hello world", "next"} {
		got, err := st.Receive(context.Background())
		if err != nil || string(got) != want {
			t.Fatalf("Receive = (%q, %v), want %q", got, err, want)
		}
	}

	fake.feed(quicFrame("kept"))
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 32; i++ {
		if got, err := st.Receive(ended); !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive %d with an ended context = (%q, %v), want context.Canceled", i, got, err)
		}
	}
	if got, err := st.Receive(context.Background()); err != nil || string(got) != "kept" {
		t.Fatalf("Receive after 32 with an ended context = (%q, %v), want kept", got, err)
	}
}

// A stream that ends is reported as io.ReadFull on the length and then on
// the payload reports it: io.EOF where no byte of the part being read had
// arrived, io.ErrUnexpectedEOF partway through one. Either way the stream
// leaves the session.
func TestQuicStream_ReceiveReportsWhereTheStreamEnded(t *testing.T) {
	frame := quicFrame("hello world")
	for name, tc := range map[string]struct {
		fed  []byte
		want error
	}{
		"between frames":          {nil, io.EOF},
		"inside the length":       {frame[:2], io.ErrUnexpectedEOF},
		"after the length":        {frame[:4], io.EOF},
		"inside the payload":      {frame[:9], io.ErrUnexpectedEOF},
		"after one whole frame":   {frame, nil},
		"inside the second frame": {append(append([]byte(nil), frame...), frame[:6]...), nil},
	} {
		fake := newFedStream()
		sess := newAEH01Session(t)
		st := registerAEH01Stream(sess, 1, fake)
		fake.feed(tc.fed)
		fake.end()
		got, err := st.Receive(context.Background())
		if tc.want == nil {
			if err != nil || string(got) != "hello world" {
				t.Errorf("%s: Receive = (%q, %v), want the whole first frame", name, got, err)
			}
			continue
		}
		if err != tc.want {
			t.Errorf("%s: Receive = (%q, %v), want %v", name, got, err, tc.want)
		}
		if n := mapLen(sess); n != 0 {
			t.Errorf("%s: the session holds %d streams after the stream ended, want 0", name, n)
		}
	}
}

// A length above aether.MaxPayloadSize is refused as soon as it is read,
// before Receive allocates or reads a payload of that size, and the stream
// leaves the session: its framing is lost.
func TestQuicStream_ReceiveRefusesAnOversizedFrame(t *testing.T) {
	fake := newFedStream()
	sess := newAEH01Session(t)
	st := registerAEH01Stream(sess, 1, fake)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], aether.MaxPayloadSize+1)
	fake.feed(length[:])
	fake.end()
	got, err := st.Receive(context.Background())
	if err == nil || !strings.Contains(err.Error(), "message too large") {
		t.Fatalf("Receive of a %d-byte length = (%d bytes, %v), want the oversize refusal", aether.MaxPayloadSize+1, len(got), err)
	}
	if n := mapLen(sess); n != 0 {
		t.Fatalf("the session holds %d streams after an oversized frame, want 0", n)
	}
}

// A Read on a GrpcStreamAdapter's net.Conn view whose receive function
// blocks returns at its read deadline, and the stream stays usable. The
// receive function that Read left running takes the next message, and a
// later Read returns that message instead of starting a second call: no
// message is lost and the receive function never runs twice at once.
func TestGrpcStreamAdapterConn_BlockedReadReturnsAtReadDeadline(t *testing.T) {
	msgs := make(chan []byte)
	var mu sync.Mutex
	var calls, running, most int
	recv := func() ([]byte, error) {
		mu.Lock()
		calls++
		running++
		most = max(most, running)
		mu.Unlock()
		defer func() {
			mu.Lock()
			running--
			mu.Unlock()
		}()
		m, ok := <-msgs
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	}
	counts := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return calls, most
	}
	// deliver hands m to the receive function, which must be waiting or
	// about to be called.
	deliver := func(m string) {
		t.Helper()
		select {
		case msgs <- []byte(m):
		case <-time.After(streamHangBound):
			t.Fatalf("no receive function took %q within %v", m, streamHangBound)
		}
	}
	a := NewGrpcStreamAdapter(1, aether.StreamConfig{}, func([]byte) error { return nil }, recv, nil)
	defer close(msgs)
	c := a.Conn()

	// Three Reads in a row time out; they share one receive function call.
	for i := 0; i < 3; i++ {
		deadline := time.Now().Add(100 * time.Millisecond)
		if err := c.SetReadDeadline(deadline); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		awaitTimedOutRead(t, readAsync(c), deadline)
	}
	if n, most := counts(); n != 1 || most != 1 {
		t.Fatalf("after three timed-out Reads the receive function was called %d times, %d at once; want 1 and 1", n, most)
	}

	if err := c.SetReadDeadline(time.Now().Add(streamHangBound)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	deliver("late")
	awaitRead(t, readAsync(c), "late")
	if n, _ := counts(); n != 1 {
		t.Fatalf("the Read after the timeouts made call %d of the receive function, want the message from call 1", n)
	}

	next := readAsync(c)
	deliver("next")
	awaitRead(t, next, "next")
	if n, most := counts(); n != 2 || most != 1 {
		t.Fatalf("receive function called %d times, %d at once; want 2 and 1", n, most)
	}

	// A Read whose deadline has already passed takes nothing: the message
	// the receive function returned is still there for the next Read. The
	// test waits until that result is in recvPending, where a Read could
	// take it at once; from then on a Read that chose between the result
	// and its ended context would take the result half the time, so 32
	// tries leave it a 2^-32 chance of passing. Only Reads write the
	// recvPending field and none is running here, so reading it is safe.
	deadline := time.Now().Add(50 * time.Millisecond)
	if err := c.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	awaitTimedOutRead(t, readAsync(c), deadline)
	deliver("held")
	for waited := time.Now(); len(a.recvPending) == 0; time.Sleep(time.Millisecond) {
		if time.Since(waited) > streamHangBound {
			t.Fatalf("the receive function's result was not kept within %v", streamHangBound)
		}
	}
	for i := 0; i < 32; i++ {
		if n, err := c.Read(make([]byte, 64)); !timedOut(err) || n != 0 {
			t.Fatalf("Read %d past its deadline = (%d, %v), want (0, a timeout)", i, n, err)
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(zero): %v", err)
	}
	awaitRead(t, readAsync(c), "held")
}
