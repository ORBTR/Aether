/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// Tests for StreamAcceptor's per-ID backlog, its grace expiry and the FIFO.
//
// The 100 ms hand-off below decides which consumer a stream reaches. Inside the
// grace only an AcceptStreamByID claim takes it; past it the stream is in the
// FIFO, where Accept and a later AcceptStreamByID of its ID both take it, first
// come first served. The mesh host outside this repository claims its setup
// streams 0-4 by ID one after another before its Accept loop starts, so a setup
// stream whose OPEN came early is still its claimant's; it claims its swarm stream
// (100) by ID from a goroutine while that loop runs, and a stream the loop takes
// first reaches its dynamic-RPC handler, which cannot read swarm frames. An ID in
// StreamAcceptorConfig.Claimed has no grace and never reaches the loop, which is
// how such a host keeps its late claims (SessionOptions.ClaimedStreams).
//
// READ A FAILURE HERE AS "THE DISPATCH CONTRACT CHANGED", not as a flake. Each
// test names what its own failure means.

// graceProbeStream is a minimal Stream for driving the acceptor. Only StreamID
// is ever consulted by StreamAcceptor; the rest satisfy the interface.
type graceProbeStream struct{ id uint64 }

func (s *graceProbeStream) StreamID() uint64                        { return s.id }
func (s *graceProbeStream) Send(context.Context, []byte) error      { return nil }
func (s *graceProbeStream) Receive(context.Context) ([]byte, error) { return nil, nil }
func (s *graceProbeStream) Close() error                            { return nil }
func (s *graceProbeStream) Reset(ResetReason) error                 { return nil }
func (s *graceProbeStream) SetPriority(uint8, uint64)               {}
func (s *graceProbeStream) Config() StreamConfig                    { return StreamConfig{StreamID: s.id} }
func (s *graceProbeStream) IsOpen() bool                            { return true }
func (s *graceProbeStream) Conn() net.Conn                          { return nil }

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

	// And it must never have reached the FIFO: an AcceptStream consumer
	// picking this up is the misroute the whole mechanism exists to prevent.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if s, err := a.Accept(ctx); err == nil {
		t.Errorf("stream %d reached the FIFO despite a pre-armed ByID waiter — a "+
			"FIFO AcceptStream consumer can now steal well-known streams", s.StreamID())
	}
}

// TestStreamAcceptor_AStreamPastItsGraceIsStillItsClaimants: no waiter is armed
// at Notify time and the grace lapses before the claim, the delay a consumer loses
// to goroutine scheduling at session establishment. With no Accept running the
// stream is in the FIFO, and the AcceptByID of its ID takes it from there, so it
// reaches the consumer that asked for it and no other.
func TestStreamAcceptor_AStreamPastItsGraceIsStillItsClaimants(t *testing.T) {
	a := newProbeAcceptor()
	st := &graceProbeStream{id: 100}

	if !a.Notify(st) {
		t.Fatal("Notify reported the stream undelivered onto an empty backlog")
	}
	time.Sleep(ByIDBacklogGrace + 150*time.Millisecond)

	byIDCtx, cancelByID := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelByID()
	s, err := a.AcceptByID(byIDCtx, 100)
	if err != nil || s != st {
		t.Fatalf("AcceptByID(100) after the grace: %v, %v; the stream it asked for is in "+
			"the FIFO and setup would hang waiting for it", s, err)
	}
	fifoCtx, cancelFIFO := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelFIFO()
	if dup, err := a.Accept(fifoCtx); err == nil {
		t.Fatalf("Accept also delivered stream %d, which AcceptByID already took: one "+
			"stream reached two consumers", dup.StreamID())
	}
}

// TestStreamAcceptor_AStreamPastItsGraceReachesAccept: a stream nobody claims by ID
// reaches the FIFO consumer once its grace lapses, the path dynamic streams take.
func TestStreamAcceptor_AStreamPastItsGraceReachesAccept(t *testing.T) {
	a := newProbeAcceptor()
	st := &graceProbeStream{id: 10}
	if !a.Notify(st) {
		t.Fatal("Notify reported the stream undelivered onto an empty backlog")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := a.Accept(ctx)
	if err != nil || s != st {
		t.Fatalf("Accept after the grace: %v, %v; the stream reached no consumer", s, err)
	}
}

// TestStreamAcceptor_AcceptByIDTakesFromTheFIFOAndKeepsItsOrder: AcceptByID takes
// the stream of its ID out of the middle of the FIFO, and Accept still reads the
// others in arrival order. Five streams: a take that filled the gap with the last
// stream would hand Accept 13 before 12 (with fewer, two such takes in a row can
// put the order back).
func TestStreamAcceptor_AcceptByIDTakesFromTheFIFOAndKeepsItsOrder(t *testing.T) {
	a := newProbeAcceptor()
	first, middle := &graceProbeStream{id: 10}, &graceProbeStream{id: 11}
	third, fourth, last := &graceProbeStream{id: 12}, &graceProbeStream{id: 13}, &graceProbeStream{id: 14}
	for _, st := range []*graceProbeStream{first, middle, third, fourth, last} {
		if !a.pushFIFO(st) {
			t.Fatalf("premise: the FIFO refused stream %d", st.id)
		}
	}
	if s, err := a.AcceptByID(context.Background(), 11); err != nil || s != middle {
		t.Fatalf("AcceptByID(11): %v, %v", s, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, want := range []*graceProbeStream{first, third, fourth, last} {
		if s, err := a.Accept(ctx); err != nil || s != want {
			t.Fatalf("Accept: %v, %v; want stream %d next", s, err, want.id)
		}
	}
}

// TestStreamAcceptor_ABlockedPushTakesTheRoomAcceptByIDMakes: under BlockUntilClose
// a push onto a full FIFO waits, and the room AcceptByID makes by taking a stream
// lets it in.
func TestStreamAcceptor_ABlockedPushTakesTheRoomAcceptByIDMakes(t *testing.T) {
	a := NewStreamAcceptor(StreamAcceptorConfig{Mode: BlockUntilClose, BufferSize: 1, Closed: make(chan struct{})})
	held, waiting := &graceProbeStream{id: 5}, &graceProbeStream{id: 6}
	if !a.pushFIFO(held) {
		t.Fatal("premise: the FIFO refused its first stream")
	}
	pushed := make(chan bool, 1)
	go func() { pushed <- a.pushFIFO(waiting) }()
	select {
	case <-pushed:
		t.Fatal("a push onto a full FIFO returned without waiting")
	case <-time.After(50 * time.Millisecond):
	}
	if s, err := a.AcceptByID(context.Background(), 5); err != nil || s != held {
		t.Fatalf("AcceptByID(5): %v, %v", s, err)
	}
	select {
	case ok := <-pushed:
		if !ok {
			t.Fatal("the waiting push was refused after AcceptByID made room")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting push did not take the room AcceptByID made")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s, err := a.Accept(ctx); err != nil || s != waiting {
		t.Fatalf("Accept: %v, %v; want the stream whose push waited", s, err)
	}
}

// TestStreamAcceptor_CloseHandsBackWhatTheFIFOHolds: Close returns the streams
// still in the FIFO with the backlog's, so the session's teardown resets them, and
// Accept then answers the close.
func TestStreamAcceptor_CloseHandsBackWhatTheFIFOHolds(t *testing.T) {
	a := newProbeAcceptor()
	queued := &graceProbeStream{id: 10}
	if !a.pushFIFO(queued) {
		t.Fatal("premise: the FIFO refused the stream")
	}
	drained := a.Close()
	if len(drained) != 1 || drained[0] != queued {
		t.Fatalf("Close returned %v, want the stream the FIFO held", drained)
	}
	if s, err := a.Accept(context.Background()); err != ErrSessionClosed || s != nil {
		t.Fatalf("Accept after Close: %v, %v; want ErrSessionClosed", s, err)
	}
	if a.pushFIFO(&graceProbeStream{id: 11}) {
		t.Fatal("a closed acceptor took a stream onto its FIFO")
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
// This is not a tautological assertion on a constant: it is a tripwire. The mesh
// host outside this repository arms AcceptStreamByID(100) from a freshly-spawned
// goroutine while its Accept loop runs, so shrinking this value narrows the window
// that goroutine has to win. Anyone retuning it should be told what else depends
// on it, here, at build time.
func TestStreamAcceptor_GraceConstantIsLoadBearing(t *testing.T) {
	if ByIDBacklogGrace != 100*time.Millisecond {
		t.Errorf("ByIDBacklogGrace changed to %v. That is allowed, but it moves the "+
			"window in which a consumer spawned as a goroutine must call "+
			"AcceptStreamByID while an Accept loop runs — the mesh host's swarm "+
			"transport (stream 100) does exactly that from its session hook. SHRINKING it "+
			"makes it likelier that the Accept loop takes such a stream first; "+
			"a consumer that pre-arms, as this file's negative control does, "+
			"never meets the race", ByIDBacklogGrace)
	}
	if MaxByIDBacklogPerStream < 1 {
		t.Errorf("MaxByIDBacklogPerStream = %d disables the backlog entirely, so "+
			"EVERY unclaimed stream goes straight to the FIFO with no grace at all",
			MaxByIDBacklogPerStream)
	}
}

// refusalRecorder is a StreamAcceptorConfig.Refuse that records what it was handed.
type refusalRecorder struct {
	mu  sync.Mutex
	got []Stream
}

func (r *refusalRecorder) refuse(st Stream) {
	r.mu.Lock()
	r.got = append(r.got, st)
	r.mu.Unlock()
}

func (r *refusalRecorder) refused() []Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Stream(nil), r.got...)
}

// TestStreamAcceptor_AStreamTheFIFOHasNoRoomForIsRefused: under NonBlockingDrop a
// stream the full FIFO cannot take goes to Refuse, by each path that reaches the
// FIFO: a backlog entry whose grace runs out, and a Notify past a full backlog. A
// stream nothing holds would otherwise keep its session's slot, reservation and queue
// while its opener waits on it.
func TestStreamAcceptor_AStreamTheFIFOHasNoRoomForIsRefused(t *testing.T) {
	rec := &refusalRecorder{}
	a := NewStreamAcceptor(StreamAcceptorConfig{Mode: NonBlockingDrop, BufferSize: 1, Refuse: rec.refuse})
	if !a.pushFIFO(&graceProbeStream{id: 10}) {
		t.Fatal("premise: the FIFO refused its first stream")
	}
	aged := &graceProbeStream{id: 12}
	if !a.Notify(aged) {
		t.Fatal("Notify reported the stream undelivered onto an empty backlog")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.refused()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rec.refused(); len(got) != 1 || got[0] != aged {
		t.Fatalf("refused %v after the grace, want the stream whose grace ran out onto a full FIFO", got)
	}
	var parked []*graceProbeStream
	for i := 0; i < MaxByIDBacklogPerStream; i++ {
		st := &graceProbeStream{id: 14}
		parked = append(parked, st)
		if !a.Notify(st) {
			t.Fatalf("Notify %d of id 14 refused with backlog room", i)
		}
	}
	past := &graceProbeStream{id: 14}
	if a.Notify(past) {
		t.Fatal("Notify past a full backlog onto a full FIFO reported the stream delivered")
	}
	// The parked streams' graces run out onto the same full FIFO, so each of them is
	// refused too: every stream but the one the FIFO holds, exactly once.
	want := map[Stream]bool{aged: true, past: true}
	for _, st := range parked {
		want[st] = true
	}
	deadline = time.Now().Add(5 * time.Second)
	for len(rec.refused()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := rec.refused()
	seen := map[Stream]bool{}
	for _, st := range got {
		if !want[st] || seen[st] {
			t.Fatalf("refused %v: stream %p refused twice or never notified", got, st)
		}
		seen[st] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("refused %d streams, want %d (the aged one, the one past the backlog and the %d parked)",
			len(seen), len(want), len(parked))
	}
}

// TestStreamAcceptor_ANotifyOnAClosedAcceptorIsRefused: Close has handed back what
// the acceptor held for the session's teardown to reset; a stream notified after it is
// handed to Refuse, so it is not left to nobody.
func TestStreamAcceptor_ANotifyOnAClosedAcceptorIsRefused(t *testing.T) {
	rec := &refusalRecorder{}
	a := NewStreamAcceptor(StreamAcceptorConfig{Mode: NonBlockingDrop, Refuse: rec.refuse})
	a.Close()
	late := &graceProbeStream{id: 10}
	if a.Notify(late) {
		t.Fatal("a closed acceptor reported a stream delivered")
	}
	if got := rec.refused(); len(got) != 1 || got[0] != late {
		t.Fatalf("refused %v, want the stream notified after Close", got)
	}
}

// TestStreamAcceptor_AClaimedStreamWaitsForItsClaimantWhileAcceptRuns: an ID in
// Claimed has no grace: while an Accept loop runs, its stream stays on the backlog
// past ByIDBacklogGrace, Accept never sees it, and an AcceptByID armed long after
// takes it. Without the claim the loop takes it (TestStreamAcceptor_AStreamPastItsGraceReachesAccept).
func TestStreamAcceptor_AClaimedStreamWaitsForItsClaimantWhileAcceptRuns(t *testing.T) {
	a := NewStreamAcceptor(StreamAcceptorConfig{Mode: NonBlockingDrop, Claimed: []uint64{101}})
	loopCtx, stopLoop := context.WithCancel(context.Background())
	defer stopLoop()
	took := make(chan Stream, 1)
	go func() {
		if st, err := a.Accept(loopCtx); err == nil {
			took <- st
		}
	}()
	st := &graceProbeStream{id: 101}
	if !a.Notify(st) {
		t.Fatal("Notify refused a claimed stream onto an empty backlog")
	}
	time.Sleep(3 * ByIDBacklogGrace)
	select {
	case got := <-took:
		t.Fatalf("the Accept loop took claimed stream %d", got.StreamID())
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := a.AcceptByID(ctx, 101); err != nil || got != st {
		t.Fatalf("the late claimant: %v, %v", got, err)
	}
	unclaimed := &graceProbeStream{id: 10}
	if !a.Notify(unclaimed) {
		t.Fatal("Notify refused an unclaimed stream onto an empty backlog")
	}
	select {
	case got := <-took:
		if got != unclaimed {
			t.Fatalf("the Accept loop took stream %d, want the unclaimed 10", got.StreamID())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an unclaimed stream did not reach the Accept loop past its grace")
	}
}

// TestStreamAcceptor_AClaimedIDPastItsBacklogIsRefused: a claimed ID's streams never
// fall through to the FIFO; the one past MaxByIDBacklogPerStream waiting unclaimed is
// refused, and the claimant then takes the waiting ones in arrival order.
func TestStreamAcceptor_AClaimedIDPastItsBacklogIsRefused(t *testing.T) {
	rec := &refusalRecorder{}
	a := NewStreamAcceptor(StreamAcceptorConfig{Mode: NonBlockingDrop, Refuse: rec.refuse, Claimed: []uint64{100}})
	var parked []*graceProbeStream
	for i := 0; i < MaxByIDBacklogPerStream; i++ {
		st := &graceProbeStream{id: 100}
		parked = append(parked, st)
		if !a.Notify(st) {
			t.Fatalf("Notify %d refused with backlog room", i)
		}
	}
	past := &graceProbeStream{id: 100}
	if a.Notify(past) {
		t.Fatal("Notify past a claimed ID's full backlog reported the stream delivered")
	}
	if got := rec.refused(); len(got) != 1 || got[0] != past {
		t.Fatalf("refused %v, want the stream past the claimed ID's backlog", got)
	}
	a.mu.Lock()
	inFIFO := len(a.fifo)
	a.mu.Unlock()
	if inFIFO != 0 {
		t.Fatalf("the FIFO holds %d streams of a claimed ID", inFIFO)
	}
	for i, want := range parked {
		if got, err := a.AcceptByID(context.Background(), 100); err != nil || got != want {
			t.Fatalf("AcceptByID %d: %v, %v; want the streams in arrival order", i, got, err)
		}
	}
}
