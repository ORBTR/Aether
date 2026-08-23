/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"net"
	"testing"
	"time"
)

// First tests for StreamAcceptor's per-ID backlog and grace-expiry dispatch.
//
// WHY THIS FILE DID NOT EXIST AND WHY IT MATTERS: the 100 ms hand-off below
// decides whether a well-known stream reaches the consumer that asked for it by
// ID, or is diverted to the legacy FIFO where some *other* consumer picks it up.
// loom's swarm transport binds stream 100 through AcceptStreamByID from a
// goroutine spawned at session-establishment time, so it is racing this timer on
// every single mesh session — and nothing here was covered.
//
// The mesh consequence of losing that race is NOT a stalled stream: the stream
// exists on the responder (handleOpen created it), so its frames are ACKed and
// drain. It is diverted into loom's dynamic-RPC handler, which accepts any
// StreamID, fails to unmarshal swarm frames as RPC requests, and discards them
// forever. Silent total loss on that peer, with a healthy-looking session.
//
// ⚠ READ A FAILURE HERE AS "THE DISPATCH CONTRACT CHANGED", not as a flake. Each
// test names what its own failure means.

// graceProbeStream is a minimal Stream for driving the acceptor. Only StreamID
// is ever consulted by StreamAcceptor; the rest satisfy the interface.
type graceProbeStream struct{ id uint64 }

func (s *graceProbeStream) StreamID() uint64                          { return s.id }
func (s *graceProbeStream) Send(context.Context, []byte) error        { return nil }
func (s *graceProbeStream) Receive(context.Context) ([]byte, error)   { return nil, nil }
func (s *graceProbeStream) Close() error                              { return nil }
func (s *graceProbeStream) Reset(ResetReason) error                   { return nil }
func (s *graceProbeStream) SetPriority(uint8, uint64)                 {}
func (s *graceProbeStream) Config() StreamConfig                      { return StreamConfig{StreamID: s.id} }
func (s *graceProbeStream) IsOpen() bool                              { return true }
func (s *graceProbeStream) Conn() net.Conn                            { return nil }

// newProbeAcceptor builds an acceptor in the mode the Noise transport uses
// (NonBlockingDrop), which is the configuration the mesh actually runs.
func newProbeAcceptor() *StreamAcceptor {
	return NewStreamAcceptor(StreamAcceptorConfig{Mode: NonBlockingDrop})
}

// waitForWaiter blocks until an AcceptByID waiter is registered for streamID.
// In-package field access is deliberate: without it the "pre-armed waiter" test
// would have to sleep and hope, which is exactly the kind of timing assumption
// this file exists to remove.
func waitForWaiter(t *testing.T, a *StreamAcceptor, streamID uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		_, armed := a.waiters[streamID]
		a.mu.Unlock()
		if armed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no AcceptByID waiter was ever registered — the acceptor's waiter " +
		"bookkeeping changed and every test in this file depends on it")
}

// TestStreamAcceptor_PreArmedWaiterBypassesBacklog is the NEGATIVE CONTROL and
// the healthy path. It is also the arrangement aether's own MaxByIDBacklogPerStream
// comment assumes: "mesh consumers normally pre-arm AcceptStreamByID for every
// well-known stream BEFORE the peer can open them".
//
// A waiter armed before Notify must claim the stream immediately, with the
// backlog and the FIFO never involved — so no timer can divert it and there is
// no race to lose.
func TestStreamAcceptor_PreArmedWaiterBypassesBacklog(t *testing.T) {
	a := newProbeAcceptor()
	st := &graceProbeStream{id: 100}

	got := make(chan Stream, 1)
	go func() {
		s, err := a.AcceptByID(context.Background(), 100)
		if err == nil {
			got <- s
		}
	}()
	waitForWaiter(t, a, 100)

	if !a.Notify(st) {
		t.Fatal("Notify reported the stream undelivered while a waiter was armed")
	}

	select {
	case s := <-got:
		if s != st {
			t.Fatalf("pre-armed waiter got the wrong stream: %v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a PRE-ARMED AcceptByID waiter did not receive the stream. This is " +
			"the healthy path — if it breaks, well-known streams cannot be bound " +
			"reliably by ANY consumer and the grace timer is no longer a mitigation")
	}

	// And it must never have reached the FIFO: a legacy AcceptStream consumer
	// picking this up is the misroute the whole mechanism exists to prevent.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if s, err := a.Accept(ctx); err == nil {
		t.Errorf("stream %d reached the FIFO despite a pre-armed ByID waiter — a "+
			"legacy AcceptStream consumer can now steal well-known streams", s.StreamID())
	}
}

// TestStreamAcceptor_GraceExpiryDivertsToFIFO is the POSITIVE CONTROL: it proves
// this file can SEE the defect, not merely that the healthy path works.
//
// No waiter is armed at Notify time — precisely loom's situation, where the
// AcceptStreamByID call lives in a goroutine spawned from the session hook. Once
// ByIDBacklogGrace elapses, flushBacklogEntry moves the stream to the FIFO and
// the ByID consumer can NEVER claim it, no matter how long it waits.
func TestStreamAcceptor_GraceExpiryDivertsToFIFO(t *testing.T) {
	a := newProbeAcceptor()
	st := &graceProbeStream{id: 100}

	if !a.Notify(st) {
		t.Fatal("Notify reported the stream undelivered onto an empty backlog")
	}

	// Let the grace lapse — the delay a real consumer loses to goroutine
	// scheduling at session establishment.
	time.Sleep(ByIDBacklogGrace + 150*time.Millisecond)

	// THE DEFECT: the consumer that asked for this exact StreamID cannot get it.
	byIDCtx, cancelByID := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelByID()
	if s, err := a.AcceptByID(byIDCtx, 100); err == nil {
		t.Fatalf("AcceptByID(100) still claimed the stream (%v) after the grace "+
			"expired. If a retry or a re-park was added this is an IMPROVEMENT — "+
			"update this test to bound the new behaviour rather than deleting it",
			s.StreamID())
	}

	// ...and the legacy FIFO consumer has it instead. This is the hand-off that
	// puts a swarm stream into loom's dynamic-RPC handler.
	fifoCtx, cancelFIFO := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFIFO()
	s, err := a.Accept(fifoCtx)
	if err != nil {
		t.Fatalf("after grace expiry the stream reached NEITHER the ByID consumer "+
			"nor the FIFO — it was lost outright, which is worse than the diversion "+
			"this test was written to pin: %v", err)
	}
	if s != st {
		t.Fatalf("FIFO delivered a different stream than the one notified: %v", s)
	}
}

// TestStreamAcceptor_ClaimWithinGraceKeepsItOffTheFIFO is the RECALL control: the
// grace genuinely works when the claim lands inside it, so the window — not the
// mechanism — is what loom is up against.
//
// Without this, the two tests above are consistent with "the backlog never
// works" and the 100 ms value would look irrelevant.
func TestStreamAcceptor_ClaimWithinGraceKeepsItOffTheFIFO(t *testing.T) {
	a := newProbeAcceptor()
	st := &graceProbeStream{id: 100}

	if !a.Notify(st) {
		t.Fatal("Notify reported the stream undelivered onto an empty backlog")
	}

	// Claim immediately — well inside ByIDBacklogGrace.
	s, err := a.AcceptByID(context.Background(), 100)
	if err != nil {
		t.Fatalf("a claim placed INSIDE the grace window failed: %v — the backlog "+
			"is not serving its purpose at all", err)
	}
	if s != st {
		t.Fatalf("backlog returned the wrong stream: %v", s)
	}

	// The flush timer is still pending; it must find the entry already drained
	// and do nothing. If it double-delivers, one stream reaches two consumers.
	time.Sleep(ByIDBacklogGrace + 150*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if dup, err := a.Accept(ctx); err == nil {
		t.Errorf("the grace timer ALSO pushed stream %d onto the FIFO after "+
			"AcceptByID had already claimed it — one stream delivered to two "+
			"consumers, and the swarm frames would be split between them",
			dup.StreamID())
	}
}

// TestStreamAcceptor_GraceConstantIsLoadBearing pins the value itself, because a
// consumer outside this package depends on it and cannot see it change.
//
// This is not a tautological assertion on a constant: it is a tripwire. loom
// arms AcceptStreamByID(100) from a freshly-spawned goroutine, so shrinking this
// value narrows the window that goroutine has to win. Anyone retuning it should
// be told what else depends on it, here, at build time.
func TestStreamAcceptor_GraceConstantIsLoadBearing(t *testing.T) {
	if ByIDBacklogGrace != 100*time.Millisecond {
		t.Errorf("ByIDBacklogGrace changed to %v. That is allowed, but it moves the "+
			"window in which a consumer spawned as a goroutine must call "+
			"AcceptStreamByID — loom's swarm transport (stream 100) does exactly "+
			"that from its session hook. SHRINKING it makes the diversion in "+
			"TestStreamAcceptor_GraceExpiryDivertsToFIFO more likely in production; "+
			"the durable fix is for consumers to pre-arm, as this file's "+
			"negative control demonstrates", ByIDBacklogGrace)
	}
	if MaxByIDBacklogPerStream < 1 {
		t.Errorf("MaxByIDBacklogPerStream = %d disables the backlog entirely, so "+
			"EVERY unclaimed stream goes straight to the FIFO with no grace at all",
			MaxByIDBacklogPerStream)
	}
}
