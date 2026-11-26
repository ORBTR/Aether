//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// openRetrying opens id on s, trying again while the ID is still held by a stream that
// ended (aether.ErrDuplicateStreamID: its RESET unacknowledged, or within the reopen
// quiet after it), for up to within. It returns the error rather than failing the test,
// so a hook running off the test's goroutine can call it.
func openRetrying(ctx context.Context, s aether.Session, id uint64, within time.Duration) (aether.Stream, error) {
	start := time.Now()
	for {
		st, err := s.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err == nil || !errors.Is(err, aether.ErrDuplicateStreamID) || time.Since(start) > within {
			return st, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNoiseStream_AResetAndReopenInsideTheTickCrossesNothing: for 30 rounds a stream
// whose ACKs are lost on the path is reset, and the next stream opens under its ID,
// between the reliability tick's snapshot of s.streams and its work on it
// (tickSnapshotTaken), with frames of the ended stream still owed a retransmit. The
// tick's retransmits and probes go to the scheduler only while s.streams holds their
// stream (queueRetransmit, queueProbe) and teardown empties the ended stream's
// retransmit queue, so no peer reads a message its stream did not send, and once every
// stream has ended the session holds no connection credit and nothing in flight.
func TestNoiseStream_AResetAndReopenInsideTheTickCrossesNothing(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	const id = 940
	var dropACKs atomic.Bool
	toClient.setRule(func(f *aether.Frame) bool {
		return dropACKs.Load() && f.StreamID == id && f.Type == aether.TypeACK
	})
	type got struct {
		round int
		msg   string
	}
	reads := make(chan got, 4096)
	acceptedRound := make(chan aether.Stream, 64)
	go func() {
		for {
			st, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			acceptedRound <- st
		}
	}()
	crossed := 0
	var crossedMu sync.Mutex
	reader := func(round int, st aether.Stream) {
		for {
			b, err := st.Receive(ctx)
			if err != nil {
				return
			}
			m := string(b)
			want := fmt.Sprintf("r%03d:", round)
			if !strings.HasPrefix(m, want) && m != "open" {
				crossedMu.Lock()
				crossed++
				crossedMu.Unlock()
				reads <- got{round, m}
			}
		}
	}
	nextStreams := make(chan aether.Stream, 1)
	hookRuns := 0
	for round := 0; round < 30; round++ {
		cs, err := openRetrying(ctx, client, id, 20*time.Second)
		if err != nil {
			t.Fatalf("round %d open: %v", round, err)
		}
		if err := cs.Send(ctx, []byte("open")); err != nil {
			t.Fatalf("round %d open send: %v", round, err)
		}
		var ss aether.Stream
		select {
		case ss = <-acceptedRound:
		case <-time.After(20 * time.Second):
			t.Fatalf("round %d: nothing accepted", round)
		}
		go reader(round, ss)
		old := asNoiseStream(t, cs)
		dropACKs.Store(true)
		for k := 0; k < 3; k++ {
			if err := cs.Send(ctx, []byte(fmt.Sprintf("r%03d:%d", round, k))); err != nil {
				t.Fatalf("round %d send: %v", round, err)
			}
		}
		waitFor(t, "the old stream's frames written", func() bool {
			f, _ := old.sendWindow.HighestWritten()
			return f != nil
		})
		ran := make(chan error, 1)
		var once atomic.Bool
		hook := func(s *NoiseSession) {
			if s != client || !holdsSelf(old) || !once.CompareAndSwap(false, true) {
				return
			}
			var herr error
			defer func() { ran <- herr }()
			if herr = old.Reset(aether.ResetCancel); herr != nil {
				return
			}
			dropACKs.Store(false)
			// The next round's stream opens here, inside the tick, under the same ID.
			next, err := openRetrying(ctx, client, id, 10*time.Second)
			if err != nil {
				herr = err
				return
			}
			if err := next.Send(ctx, []byte("open")); err != nil {
				herr = err
				return
			}
			nextStreams <- next
		}
		tickSnapshotTaken.Store(&hook)
		select {
		case err := <-ran:
			tickSnapshotTaken.Store(nil)
			if err != nil {
				t.Fatalf("round %d hook: %v", round, err)
			}
			hookRuns++
		case <-time.After(20 * time.Second):
			tickSnapshotTaken.Store(nil)
			t.Fatalf("round %d: the tick never ran the hook", round)
		}
		next := <-nextStreams
		var nss aether.Stream
		select {
		case nss = <-acceptedRound:
		case <-time.After(20 * time.Second):
			t.Fatalf("round %d: the next stream was not accepted", round)
		}
		go reader(round+1000, nss)
		for k := 0; k < 3; k++ {
			if err := next.Send(ctx, []byte(fmt.Sprintf("r%03d:%d", round+1000, k))); err != nil {
				t.Fatalf("round %d next send: %v", round, err)
			}
		}
		// Let a retransmit tick or two pass with the old stream's frames owed.
		time.Sleep(300 * time.Millisecond)
		_ = next.Reset(aether.ResetCancel)
	}
	time.Sleep(time.Second)
	crossedMu.Lock()
	c := crossed
	crossedMu.Unlock()
	var sample []string
	for len(sample) < 5 {
		select {
		case g := <-reads:
			sample = append(sample, fmt.Sprintf("round %d read %q", g.round, g.msg))
			continue
		default:
		}
		break
	}
	waitForLong := func(what string, cond func() bool) bool {
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(10 * time.Millisecond)
		}
		return true
	}
	connOK := waitForLong("conn", func() bool { return client.connWindow.Stats().Outstanding == 0 })
	inflightOK := waitForLong("inflight", func() bool { return client.totalInFlightBytes() == 0 })
	t.Logf("hook runs %d, crossed %d %v, conn outstanding %d, in flight %d", hookRuns, c, sample, client.connWindow.Stats().Outstanding, client.totalInFlightBytes())
	if c != 0 {
		t.Errorf("%d messages read on a stream that did not send them: %v", c, sample)
	}
	if !connOK {
		t.Errorf("%d bytes of connection credit outstanding after every stream ended", client.connWindow.Stats().Outstanding)
	}
	if !inflightOK {
		t.Errorf("%d bytes in flight after every stream ended", client.totalInFlightBytes())
	}
}
