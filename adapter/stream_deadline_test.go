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
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// streamHangBound is how long these tests wait for something the code
// under test must do: a frame crossing a loopback QUIC connection, a
// released call returning. A passing run never waits for it. It only
// turns a hang into a failure, so it sits far above what a loaded machine
// running the race detector needs.
const streamHangBound = 30 * time.Second

// awaitClosed fails the test unless ch closes within streamHangBound.
func awaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(streamHangBound):
		t.Fatalf("%s did not happen within %v", what, streamHangBound)
	}
}

// fakeTimeout is the error a fake quic.Stream returns for a deadline that
// has passed; quicStream tells a deadline from any other failure by
// net.Error's Timeout, as it does with quic-go's own error.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "fake stream: deadline exceeded" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// A Send that timed out before any byte of its frame was accepted leaves
// the stream usable and clears the QUIC write deadline it moved: the frame
// sent before it arrives whole, the next Send goes through, and its frame
// is the next one the peer reads, so no byte of the timed-out frame was
// written.
//
// The stream is put in the one state where a frame's 4-byte length cannot
// be accepted. quic-go keeps up to 1452 bytes of a stream's writes that
// flow control holds back, and returns from Write once the rest has gone.
// The first frame is sized to end 1450 bytes past the peer's 16 KiB
// stream window, so its Send returns with those 1450 bytes held and the
// next length would make 1454. The peer reads nothing until the second
// Send has returned, so the window cannot open under it: the second Send
// can only end by its context, and the test has no race to lose.
func TestQuicStream_SendTimedOutWithNothingWrittenLeavesStreamUsable(t *testing.T) {
	const (
		window = 16 << 10                   // quicLoopback's stream receive window
		opened = 8 + aether.OpenPayloadSize // the header OpenStream wrote
		held   = 1450                       // of quic-go's 1452-byte write buffer
	)
	client, server := quicLoopback(t)
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	first := bytes.Repeat([]byte{0xA5}, window+held-opened-4)
	if err := st.Send(ctx, first); err != nil {
		t.Fatalf("Send of the frame that fills the window: %v", err)
	}
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	err = st.Send(short, []byte("timed out"))
	cancelShort()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send behind a full window and a full write buffer = %v, want context.DeadlineExceeded", err)
	}

	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if got, err := peer.Receive(ctx); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("peer Receive of the first frame = (%d bytes, %v), want its %d bytes", len(got), err, len(first))
	}
	if err := st.Send(ctx, []byte("after")); err != nil {
		t.Fatalf("Send after one that timed out with nothing written: %v", err)
	}
	if got, err := peer.Receive(ctx); err != nil || string(got) != "after" {
		t.Fatalf("peer Receive after the timed-out Send = (%q, %v), want after", got, err)
	}
}

// heldMoveStream is a quic.Stream whose Write waits for letWrite and whose
// first SetWriteDeadline to a non-zero time waits for letMove, so a test
// can hold quicStream.boundWrite's move of the deadline in flight while
// the Write it bounds returns. Like quic-go's stream, a Write that starts
// with a write deadline in the past fails with a timeout.
type heldMoveStream struct {
	fakeAEH01Stream
	writing, letWrite chan struct{}
	moving, letMove   chan struct{}
	writingOnce       sync.Once
	movingOnce        sync.Once
	mu                sync.Mutex
	deadline          time.Time
}

func newHeldMoveStream() *heldMoveStream {
	return &heldMoveStream{
		writing: make(chan struct{}), letWrite: make(chan struct{}),
		moving: make(chan struct{}), letMove: make(chan struct{}),
	}
}

func (s *heldMoveStream) Write(p []byte) (int, error) {
	s.writingOnce.Do(func() { close(s.writing) })
	<-s.letWrite
	if dl := s.writeDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
		return 0, fakeTimeout{}
	}
	return len(p), nil
}

func (s *heldMoveStream) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		s.movingOnce.Do(func() { close(s.moving) })
		<-s.letMove
	}
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}

func (s *heldMoveStream) writeDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// A later Send never meets a write deadline left in the past. The move of
// the deadline to now runs on its own goroutine once the Send's context
// ends, and the Write it bounds can return on its own while that move is
// still in flight. The Send must wait for the move before it clears the
// deadline: cleared first, the move would land afterwards and fail every
// later Send.
//
// The test holds the move in flight, lets the Write return, and requires
// that the Send has not returned 100ms later. A correct Send cannot return
// while the move is held, so that wait never fails one; the 100ms only
// gives a Send that does not wait the time to show it.
func TestQuicStream_SendClearsWriteDeadlineAfterItsMove(t *testing.T) {
	fake := newHeldMoveStream()
	st := registerAEH01Stream(newAEH01Session(t), 1, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- st.Send(ctx, []byte("first")) }()

	awaitClosed(t, fake.writing, "the Send's Write")
	cancel()
	awaitClosed(t, fake.moving, "the move of the write deadline")
	close(fake.letWrite)
	select {
	case err := <-sent:
		t.Fatalf("Send returned (%v) while the move of its write deadline was in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(fake.letMove)
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("Send whose Writes completed: %v", err)
		}
	case <-time.After(streamHangBound):
		t.Fatalf("Send did not return within %v of its move", streamHangBound)
	}

	if dl := fake.writeDeadline(); !dl.IsZero() {
		t.Fatalf("write deadline after the Send = %v, want none", dl)
	}
	if err := st.Send(context.Background(), []byte("second")); err != nil {
		t.Fatalf("later Send: %v", err)
	}
}
