//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// peerReopenInsideTheExit resets old on client and, inside its RESET's exit before the
// stream leaves the scheduler and the stream GC (beforeSchedulerExit), has the peer
// open the same ID and send on it, and waits until client publishes the peer's stream.
// It returns the peer's end of that stream.
func peerReopenInsideTheExit(t *testing.T, ctx context.Context, client, server *NoiseSession, old *noiseStream, id uint64) aether.Stream {
	t.Helper()
	type res struct {
		st  aether.Stream
		err error
	}
	done := make(chan res, 1)
	hook := func() {
		var r res
		defer func() { done <- r }()
		deadline := time.Now().Add(15 * time.Second)
		for {
			r.st, r.err = server.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
			if r.err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if r.err != nil {
			return
		}
		if r.err = r.st.Send(ctx, []byte("peer's open")); r.err != nil {
			return
		}
		for time.Now().Before(deadline) {
			client.mu.Lock()
			cur, ok := client.streams[id]
			client.mu.Unlock()
			if ok && cur != old {
				return
			}
			time.Sleep(time.Millisecond)
		}
		r.err = errors.New("the client never published the peer's stream under the ID")
	}
	old.beforeSchedulerExit.Store(&hook)
	if err := old.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("the peer's reopen inside the exit: %v", r.err)
	}
	return r.st
}

// The peer opens the ID while this side's RESET exit has not yet reached the scheduler:
// the ended stream's exit leaves the peer's stream registered, so the stream this side
// accepted for it carries traffic both ways.
func TestNoiseSession_APeerReopenInsideAResetsExitKeepsItsSchedulerRegistration(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const id = 1006
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")
	peer := peerReopenInsideTheExit(t, ctx, client, server, old, id)

	mine, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the peer's stream: %v", err)
	}
	if got, err := mine.Receive(ctx); err != nil || string(got) != "peer's open" {
		t.Fatalf("read %q, %v; want the peer's open", got, err)
	}
	sctx, scancel := context.WithTimeout(ctx, 10*time.Second)
	defer scancel()
	if err := mine.Send(sctx, []byte("reply on the reopened ID")); err != nil {
		t.Fatalf("this side's send on the peer's stream: %v", err)
	}
	if got, err := peer.Receive(sctx); err != nil || string(got) != "reply on the reopened ID" {
		t.Fatalf("the peer read %q, %v; want the reply", got, err)
	}
	if n := client.sched.StreamCount(); n < 1 {
		t.Fatalf("the scheduler holds %d registrations", n)
	}
}

// The same reopen, read on the stream GC: once the ended stream's exit has run, the
// peer's stream under the ID is still tracked for its idle timeout, under its own
// registration.
func TestNoiseSession_APeerReopenInsideAResetsExitStaysTrackedByTheStreamGC(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const id = 1008
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")
	tracked := client.streamGC.TrackedCount()
	_ = peerReopenInsideTheExit(t, ctx, client, server, old, id)
	mine, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the peer's stream: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := client.streamGC.TrackedCount(); got != tracked {
		t.Fatalf("the stream GC tracks %d streams after the ended stream's exit, want %d", got, tracked)
	}
	// The entry is the peer's stream's: its own registration's release takes it out.
	client.streamGC.UnregisterRegistration(id, uint64(asNoiseStream(t, mine).schedReg))
	if got := client.streamGC.TrackedCount(); got != tracked-1 {
		t.Fatalf("the peer's stream's registration released the GC to %d tracked, want %d", got, tracked-1)
	}
}

// The stream GC's reset names the registration it tracked: a reset for an earlier
// registration of the ID, the entry the sweep let go before the ID's present stream
// registered, leaves that stream open, published and tracked; the reset for the present
// stream's own registration ends it.
func TestNoiseSession_AnIdleResetOfAnEarlierRegistrationLeavesTheIDsStreamOpen(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const id = 1010
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	tracked := client.streamGC.TrackedCount()

	earlier := uint64(cs.schedReg) + 1000
	client.resetIdleStream(id, earlier)
	client.mu.Lock()
	cur := client.streams[id]
	client.mu.Unlock()
	if cur != cs {
		t.Fatal("a reset for an earlier registration took the ID's present stream out of the session")
	}
	if got := client.streamGC.TrackedCount(); got != tracked {
		t.Fatalf("after a reset for an earlier registration the GC tracks %d, want %d", got, tracked)
	}
	sctx, scancel := context.WithTimeout(ctx, 10*time.Second)
	defer scancel()
	if err := cs.Send(sctx, []byte("still open")); err != nil {
		t.Fatalf("send on the present stream: %v", err)
	}
	if got, err := ss.Receive(sctx); err != nil || string(got) != "still open" {
		t.Fatalf("the peer read %q, %v; want the present stream's message", got, err)
	}

	client.resetIdleStream(id, uint64(cs.schedReg))
	client.mu.Lock()
	_, still := client.streams[id]
	client.mu.Unlock()
	if still {
		t.Fatal("the reset for the present stream's registration left it in the session")
	}
	if got := client.streamGC.TrackedCount(); got != tracked-1 {
		t.Fatalf("after the present stream's reset the GC tracks %d, want %d", got, tracked-1)
	}
	if _, err := ss.Receive(sctx); err == nil {
		t.Fatal("the peer's end read on after the idle reset")
	}
}
