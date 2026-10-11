//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"testing"
	"time"
)

// tornStream is a fedStream whose Read, once the read deadline has passed,
// returns the bytes held for that moment together with the timeout.
// quic-go's Read does the same when the deadline passes after it has
// copied part of what it was asked for, so one Read hands quicStream's
// Receive bytes and an error at once.
type tornStream struct {
	*fedStream
	held []byte
}

func (s *tornStream) Read(p []byte) (int, error) {
	n, err := s.fedStream.Read(p)
	if !timedOut(err) {
		return n, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := copy(p, s.held)
	s.held = s.held[m:]
	return m, err
}

// hold queues b for the next Read that meets the passed deadline.
func (s *tornStream) hold(b []byte) {
	s.mu.Lock()
	s.held = append(s.held, b...)
	s.mu.Unlock()
}

func (s *tornStream) heldLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

// A Receive whose context ends keeps the bytes the cut-short Read
// returned beside its timeout. Ending the context moves the QUIC read
// deadline to now, and a Read that had already copied part of the frame
// returns that part with the timeout. Those bytes are kept with the rest
// of the frame read so far, so the next Receive resumes at the byte after
// them: the frame comes out whole and the frame after it is read from its
// own first byte. Each case cuts one frame, inside its payload or inside
// its length, handing the Read's bytes over with the timeout. Bytes
// dropped there would leave a frame short, and its Receive would wait for
// them: readReturnBound turns that wait into a failure.
func TestQuicStream_ReceiveKeepsBytesReadWithItsTimeout(t *testing.T) {
	frame := quicFrame("hello world")
	for _, tc := range []struct {
		where     string
		fed, held []byte
		rest      []byte
	}{
		{"inside the payload", frame[:4], frame[4:7], frame[7:]},
		{"inside the length", nil, frame[:2], frame[2:]},
	} {
		fake := &tornStream{fedStream: newFedStream()}
		sess := newAEH01Session(t)
		st := registerAEH01Stream(sess, 1, fake)
		fake.feed(tc.fed)
		fake.hold(tc.held)

		// A Receive that must wait for more, whose context then ends.
		ctx, cancel := context.WithCancel(context.Background())
		got := make(chan error, 1)
		go func() {
			_, err := st.Receive(ctx)
			got <- err
		}()
		select {
		case <-fake.waits:
		case <-time.After(streamHangBound):
			t.Fatalf("%s: Receive did not read what was fed to it", tc.where)
		}
		cancel()
		select {
		case err := <-got:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: Receive = %v, want context.Canceled", tc.where, err)
			}
		case <-time.After(readReturnBound):
			t.Fatalf("%s: Receive still blocked %v after its context ended", tc.where, readReturnBound)
		}
		if n := mapLen(sess); n != 1 {
			t.Fatalf("%s: the session holds %d streams after the Receive, want 1", tc.where, n)
		}

		fake.feed(tc.rest)
		fake.feed(quicFrame("next"))
		for _, want := range []string{"hello world", "next"} {
			ctx, cancel := context.WithTimeout(context.Background(), readReturnBound)
			got, err := st.Receive(ctx)
			cancel()
			if err != nil || string(got) != want {
				t.Fatalf("%s: Receive = (%q, %v), want %q", tc.where, got, err, want)
			}
		}
		if n := fake.heldLen(); n != 0 {
			t.Fatalf("%s: %d held bytes were never returned with a timeout, so the case did not cut the Read it names", tc.where, n)
		}
	}
}
