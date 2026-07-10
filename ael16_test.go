/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// ael16MockStream is a minimal aether.Stream used only by the AE-L-16
// teardown-race regression test. All symbols in this file are prefixed
// with ael16 because several finding-specific test files compile into
// the same root `aether` package and must not collide on identifiers.
type ael16MockStream struct {
	id       uint64
	wasReset atomic.Bool
}

func (m *ael16MockStream) StreamID() uint64                          { return m.id }
func (m *ael16MockStream) Send(ctx context.Context, data []byte) error { return nil }
func (m *ael16MockStream) Receive(ctx context.Context) ([]byte, error) { return nil, nil }
func (m *ael16MockStream) Close() error                              { return nil }
func (m *ael16MockStream) Reset(reason ResetReason) error {
	m.wasReset.Store(true)
	return nil
}
func (m *ael16MockStream) SetPriority(weight uint8, dependency uint64) {}
func (m *ael16MockStream) Config() StreamConfig                        { return StreamConfig{StreamID: m.id} }
func (m *ael16MockStream) IsOpen() bool                                { return true }
func (m *ael16MockStream) Conn() net.Conn                              { return nil }

// TestAEL16_TeardownRaceDoesNotOrphanWaiterStream exercises the window
// where session teardown closes the acceptor's `closed` channel (via
// SignalClose) BEFORE Close() sets isClosed. In that window a Notify for
// a pinned/well-known ID with an armed AcceptByID waiter still takes the
// waiter fast-path: it deletes the waiter slot and buffers the stream
// into the cap-1 channel. If AcceptByID's `case <-a.closed:` arm then
// wins the pseudo-random select it must NOT return ErrSessionClosed and
// walk away — that would orphan the buffered stream (Notify reported it
// delivered, Close() can no longer surface it because the waiter was
// already removed, and no Reset is ever sent to the peer).
//
// The fix mirrors the ctx.Done() drain: re-check the waiter map under the
// lock and, if a Notify already claimed our slot, consume the buffered
// stream and hand it back. The assertion below is that the stream is
// accounted for in exactly one place on every racing iteration — returned
// by AcceptByID, surfaced by Close (backlog fall-through), or sitting in
// the FIFO — never dropped.
//
// Pre-fix this fails within a few iterations whenever `a.closed` wins the
// select after Notify buffered the stream. Run with -race to also catch
// any send-on-closed-channel panic.
func TestAEL16_TeardownRaceDoesNotOrphanWaiterStream(t *testing.T) {
	const iterations = 2000
	const wellKnownID = 3

	for i := 0; i < iterations; i++ {
		closedCh := make(chan struct{})
		acc := NewStreamAcceptor(StreamAcceptorConfig{
			Mode:   NonBlockingDrop,
			Closed: closedCh,
		})
		st := &ael16MockStream{id: wellKnownID}

		var got Stream
		var acceptErr error
		var accWg sync.WaitGroup
		accWg.Add(1)
		go func() {
			defer accWg.Done()
			got, acceptErr = acc.AcceptByID(context.Background(), wellKnownID)
		}()

		// Wait until the waiter is registered so the race is meaningful:
		// Notify must find an armed waiter to take the fast-path.
		for {
			acc.mu.Lock()
			_, ok := acc.waiters[wellKnownID]
			acc.mu.Unlock()
			if ok {
				break
			}
			runtime.Gosched()
		}

		// Fire teardown (close the shared `closed` channel) and Notify
		// near-simultaneously behind a start barrier so `<-ch` and
		// `<-a.closed` are both ready and the select must choose.
		start := make(chan struct{})
		var raceWg sync.WaitGroup
		raceWg.Add(2)
		go func() {
			defer raceWg.Done()
			<-start
			close(closedCh)
		}()
		go func() {
			defer raceWg.Done()
			<-start
			acc.Notify(st)
		}()
		close(start)

		// Ensure both racers have fully returned before Close so a
		// backlog fall-through (Notify racing an emptied waiter map) is
		// not dropped by Close's isClosed guard.
		raceWg.Wait()
		accWg.Wait()

		drained := acc.Close()

		inFifo := false
		select {
		case s := <-acc.fifo:
			if s == Stream(st) {
				inFifo = true
			}
		default:
		}

		places := 0
		returned := got == Stream(st) && acceptErr == nil
		if returned {
			places++
		}
		inDrained := false
		for _, s := range drained {
			if s == Stream(st) {
				inDrained = true
			}
		}
		if inDrained {
			places++
		}
		if inFifo {
			places++
		}

		if places != 1 {
			t.Fatalf("AE-L-16: stream orphaned/miscounted on teardown race (iter %d): places=%d returned=%v inDrained=%v inFifo=%v acceptErr=%v",
				i, places, returned, inDrained, inFifo, acceptErr)
		}
	}
}
