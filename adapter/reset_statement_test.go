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
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// openPriorOffset is where an OPEN payload's statement of the opener's earlier
// stream under the ID begins: [PriorGeneration:8][PriorConsumed:8] follow the
// reliability, priority, dependency, initial credit, FEC level and generation.
const openPriorOffset = 23

// openStating is the OPEN payload a peer writes for generation gen under an ID whose
// earlier stream it opened, priorGen, it ended by a RESET, stating what its consumer
// returned of this side's sends on that stream (priorConsumed).
func openStating(credit uint32, gen, priorGen, priorConsumed uint64) []byte {
	p := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: aether.ReliableOrdered, Priority: 128, InitialCredit: credit, Generation: gen,
	})[:openPriorOffset]
	var prior [16]byte
	binary.BigEndian.PutUint64(prior[0:8], priorGen)
	binary.BigEndian.PutUint64(prior[8:16], priorConsumed)
	return append(p, prior[:]...)
}

// TestNoiseSession_ASupersedingOpenSettlesTheStreamItEndsOnItsStatement: a peer's OPEN
// of an ID at a higher generation ends the peer's stream this side still holds there
// (the peer's RESET of it never arrived). The OPEN states that stream's generation and
// what the peer's consumer returned of this side's sends on it, so this side gives back
// all its sends charged less that, exactly as the peer's RESET would have settled it,
// and acknowledges that RESET with its own Consumed, naming the stream as the peer's
// RESET would have, so the peer's waiting stream settles too.
func TestNoiseSession_ASupersedingOpenSettlesTheStreamItEndsOnItsStatement(t *testing.T) {
	client, server, _, toClient := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 940
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	var mu sync.Mutex
	var acks []aether.ResetPayload
	toClient.setRule(func(f *aether.Frame) bool {
		if f.StreamID == id && f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK) {
			mu.Lock()
			acks = append(acks, aether.DecodeResetPayload(f.Payload))
			mu.Unlock()
		}
		return false
	})
	msg := []byte("from the server, three times")
	for i := 0; i < 3; i++ {
		if err := ss.Send(ctx, msg); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if r := <-receiveAsync(ctx, cs, 5*time.Second); r.err != nil {
			t.Fatalf("client receive %d: %v", i, r.err)
		}
	}
	consumed := 2 * messageCredit(int64(len(msg)))
	waitFor(t, "the client's grants for two messages", func() bool { return cs.recvQ.grantedForTest() == consumed })
	waitFor(t, "the server's charge down to the unread message", func() bool {
		return connOutstanding(server) == messageCredit(int64(len(msg)))
	})

	gen := cs.incarnation.Generation
	payload := openStating(uint32(cs.window.CurrentWindow()), gen+1, gen, uint64(consumed))
	server.processIncomingFrame(&aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: server.LocalPeerID(),
		StreamID: id, Type: aether.TypeOPEN, Length: uint32(len(payload)), Payload: payload,
	}, aether.FullFrameDiscriminator)

	waitFor(t, "the superseded stream's charge returned on the OPEN's statement", func() bool { return connOutstanding(server) == 0 })
	waitFor(t, "the superseded stream's RESET acknowledged", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(acks) > 0
	})
	mu.Lock()
	ack := acks[0]
	mu.Unlock()
	want := aether.StreamIncarnation{Generation: gen, WriterOpened: true}
	if ack.Incarnation != want {
		t.Fatalf("the acknowledgment names %+v, want the opener's naming %+v", ack.Incarnation, want)
	}
	if got := int64(ack.Consumed); got != ss.recvQ.grantedForTest() || got == 0 {
		t.Fatalf("the acknowledgment states Consumed %d, want the server's consumer's %d", got, ss.recvQ.grantedForTest())
	}
}

// TestNoiseSession_AnOpenStatesTheOpenersEarlierStreamUnderItsID: an OPEN of an ID
// whose earlier stream this side opened and a RESET ended states that stream's
// generation and what this side's consumer returned of the peer's sends on it, the
// statement a peer that still holds the stream settles it on.
func TestNoiseSession_AnOpenStatesTheOpenersEarlierStreamUnderItsID(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 950
	var mu sync.Mutex
	var opens [][]byte
	toServer.setRule(func(f *aether.Frame) bool {
		if f.StreamID == id && f.Type == aether.TypeOPEN {
			mu.Lock()
			opens = append(opens, append([]byte(nil), f.Payload...))
			mu.Unlock()
		}
		return false
	})
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	msg := []byte("read once")
	for i := 0; i < 2; i++ {
		if err := ss.Send(ctx, msg); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
	}
	if r := <-receiveAsync(ctx, cs, 5*time.Second); r.err != nil {
		t.Fatalf("client receive: %v", r.err)
	}
	consumed := messageCredit(int64(len(msg)))
	waitFor(t, "the client's grant", func() bool { return cs.recvQ.grantedForTest() == consumed })
	gen := cs.incarnation.Generation
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := openRetryingDuplicate(ctx, client, id, 30*time.Second); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opens) < 2 {
		t.Fatalf("%d OPENs written, want two", len(opens))
	}
	last := opens[len(opens)-1]
	if len(last) < openPriorOffset+16 {
		t.Fatalf("the reopening OPEN is %d bytes and states no earlier stream", len(last))
	}
	priorGen := binary.BigEndian.Uint64(last[openPriorOffset : openPriorOffset+8])
	priorConsumed := binary.BigEndian.Uint64(last[openPriorOffset+8 : openPriorOffset+16])
	if priorGen != gen || int64(priorConsumed) != consumed {
		t.Fatalf("the reopening OPEN states generation %d and Consumed %d, want %d and %d", priorGen, priorConsumed, gen, consumed)
	}
	if first := opens[0]; len(first) >= openPriorOffset+16 && binary.BigEndian.Uint64(first[openPriorOffset:openPriorOffset+8]) != 0 {
		t.Fatal("the first OPEN under the ID states an earlier stream")
	}
}

// TestNoiseSession_AnOpenStatesAnEarlierStreamWhoseConsumerReturnedNothing: the
// statement names the earlier stream even when this side's consumer returned nothing
// of the peer's sends there, so a peer that still holds that stream settles it at
// Consumed 0, giving back all it charged, rather than keeping the charge.
func TestNoiseSession_AnOpenStatesAnEarlierStreamWhoseConsumerReturnedNothing(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 952
	var mu sync.Mutex
	var last []byte
	toServer.setRule(func(f *aether.Frame) bool {
		if f.StreamID == id && f.Type == aether.TypeOPEN {
			mu.Lock()
			last = append([]byte(nil), f.Payload...)
			mu.Unlock()
		}
		return false
	})
	cs, _ := openWithCredit(t, ctx, client, server, id, 0)
	gen := cs.incarnation.Generation
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := openRetryingDuplicate(ctx, client, id, 30*time.Second); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(last) < openPriorOffset+16 {
		t.Fatalf("the reopening OPEN is %d bytes", len(last))
	}
	if got := binary.BigEndian.Uint64(last[openPriorOffset : openPriorOffset+8]); got != gen {
		t.Fatalf("the reopening OPEN states earlier generation %d, want %d", got, gen)
	}
	if got := binary.BigEndian.Uint64(last[openPriorOffset+8 : openPriorOffset+16]); got != 0 {
		t.Fatalf("the reopening OPEN states Consumed %d, want 0", got)
	}
}

// TestNoiseSession_AnOpenPastTheStreamCapCountingWaitingResetsIsRefused: a stream
// whose RESET waits for the peer's statement keeps its place under the session's
// stream cap, so with the cap's worth of RESETs waiting a further open is refused
// with aether.ErrStreamCapExhausted, and no RESET is ever written without a place to
// wait for its statement; once the peer's acknowledgments come every stream's charge
// is back and the open goes through.
func TestNoiseSession_AnOpenPastTheStreamCapCountingWaitingResetsIsRefused(t *testing.T) {
	const streamCap = 3
	client, server, _, toClient := filteredPair(t, func(o *aether.SessionOptions) {
		o.SessionWarmupGrace = -1
		o.MaxConcurrentStreams = streamCap
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() {
		for {
			if _, err := server.AcceptStream(ctx); err != nil {
				return
			}
		}
	}()
	toClient.setRule(func(f *aether.Frame) bool { return f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK) })
	unread := []byte("never read")
	open := func(id uint64) (aether.Stream, error) {
		return client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
	}
	for i := 0; i < streamCap; i++ {
		st, err := open(uint64(960 + 2*i))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := st.Send(ctx, unread); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		waitFor(t, "the message charged", func() bool { return connOutstanding(client) == int64(i+1)*messageCredit(int64(len(unread))) })
		_ = st.Reset(aether.ResetCancel)
	}
	leaked := false
	st, err := open(970)
	switch {
	case err == nil:
		if err := st.Send(ctx, unread); err != nil {
			t.Fatalf("send past the cap: %v", err)
		}
		_ = st.Reset(aether.ResetCancel)
		leaked = true
	case !errors.Is(err, aether.ErrStreamCapExhausted):
		t.Fatalf("the open past the cap answered %v, want ErrStreamCapExhausted", err)
	}
	toClient.setRule(nil)
	deadline := time.Now().Add(15 * time.Second)
	for connOutstanding(client) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := connOutstanding(client); got != 0 {
		t.Fatalf("client connection outstanding %d after every acknowledgment, want 0 (a fourth stream admitted: %v)", got, leaked)
	}
	if leaked {
		t.Fatal("a fourth stream was admitted while the cap's worth of RESETs waited for their statements")
	}
	if _, err := open(970); err != nil {
		t.Fatalf("the open once the statements came: %v", err)
	}
}

// TestNoiseSession_EachResetUnderAnIDWaitsForItsOwnAcknowledgment: a RESET of the
// peer's stream under an ID, and a RESET of the stream the peer opened next under it,
// are each written again until their own acknowledgment comes, so the earlier one is
// not dropped by the later one, and both streams' charges come back.
func TestNoiseSession_EachResetUnderAnIDWaitsForItsOwnAcknowledgment(t *testing.T) {
	client, server, _, toClient := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 980
	ss1, cs1 := openWithCredit(t, ctx, server, client, id, 0)
	_ = ss1
	unread := []byte("the server never reads this")
	if err := cs1.Send(ctx, unread); err != nil {
		t.Fatalf("send on the first stream: %v", err)
	}
	waitFor(t, "first charge", func() bool { return connOutstanding(client) == messageCredit(int64(len(unread))) })
	toClient.setRule(func(f *aether.Frame) bool { return f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK) })
	_ = cs1.Reset(aether.ResetCancel)

	ss2, err := openRetryingDuplicate(ctx, server, id, 30*time.Second)
	if err != nil {
		t.Fatalf("server reopen: %v", err)
	}
	if err := ss2.Send(ctx, []byte("second")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	var cs2 aether.Stream
	for cs2 == nil {
		st, err := client.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if st.StreamID() == id {
			cs2 = st
		}
	}
	if r := <-receiveAsync(ctx, cs2, 5*time.Second); r.err != nil || string(r.data) != "second" {
		t.Fatalf("second stream read %q, %v", r.data, r.err)
	}
	if err := cs2.Send(ctx, unread); err != nil {
		t.Fatalf("send on the second stream: %v", err)
	}
	waitFor(t, "second charge", func() bool { return connOutstanding(client) == 2*messageCredit(int64(len(unread))) })
	_ = cs2.Reset(aether.ResetCancel)
	time.Sleep(300 * time.Millisecond)
	toClient.setRule(nil)
	deadline := time.Now().Add(15 * time.Second)
	for connOutstanding(client) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := connOutstanding(client); got != 0 {
		t.Fatalf("client connection outstanding %d once acknowledgments flow, want 0", got)
	}
}
