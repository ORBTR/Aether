//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
)

// reopenWithin opens id on client again once the ID is free, as a caller does after
// a Reset: the ID stays closed to a local open until the peer acknowledges the RESET
// and for a few RTOs after (createStream's resetPendingLocked and reopenQuietLocked).
func reopenWithin(t *testing.T, ctx context.Context, client *NoiseSession, id uint64, within time.Duration) *noiseStream {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err == nil {
			return asNoiseStream(t, st)
		}
		if time.Now().After(deadline) {
			t.Fatalf("reopen %d: %v", id, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// deferringPacer is the session's pacer with one deferral the test arms: the next
// TimeUntilSend after arm runs the armed hook, on the write loop's goroutine, between
// the write loop's taking the frame and its acting on the answer, and then answers the
// armed wait, so the write loop defers the frame it has and parks on its pacing timer
// for that long, taking nothing else meanwhile.
type deferringPacer struct {
	congestion.PacingPolicy
	wait  atomic.Int64
	hook  atomic.Pointer[func()]
	asked atomic.Int64
}

func (p *deferringPacer) arm(d time.Duration, hook func()) {
	if hook != nil {
		p.hook.Store(&hook)
	}
	p.wait.Store(int64(d))
}

func (p *deferringPacer) TimeUntilSend(n int) time.Duration {
	if w := p.wait.Swap(0); w > 0 {
		if h := p.hook.Swap(nil); h != nil {
			(*h)()
		}
		p.asked.Add(1)
		return time.Duration(w)
	}
	return p.PacingPolicy.TimeUntilSend(n)
}

// deferPacing puts a deferringPacer in front of client's pacer. Called before the
// session's first scheduled frame: the write loop reads s.pacer only after it takes
// a frame the test's later Send queued, which orders this write before that read.
func deferPacing(client *NoiseSession) *deferringPacer {
	p := &deferringPacer{PacingPolicy: client.pacer}
	client.pacer = p
	return p
}

// TestNoiseStream_AHeldFrameOfAnEndedStreamStaysOffTheIDsNextStream: the write loop
// holds a DATA frame the pacer deferred, and while it waits on its pacing timer the
// frame's stream is reset and the next stream opens under the same ID. The frame
// belongs to the stream that ended, whose registration the RESET's exit removed
// (releaseStream, Scheduler.UnregisterRegistration), so the write loop drops it
// (frameStream) as Scheduler.Unregister drops what the stream still had queued, and the next stream's peer reads only what the next stream sent.
// A write loop that looks the frame's stream up by ID writes it on the next stream's
// send window instead, and the next stream's peer reads it as its own.
func TestNoiseStream_AHeldFrameOfAnEndedStreamStaysOffTheIDsNextStream(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	pacer := deferPacing(client)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const id = 960
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")

	const hold = 6 * time.Second
	pacer.arm(hold, nil)
	heldAt := time.Now()
	if err := old.Send(ctx, []byte("ended stream's frame")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, "the ended stream's frame held by the pacer", func() bool {
		f, _ := old.sendWindow.HighestWritten()
		return pacer.asked.Load() == 1 && f == nil && old.sendWindow.InFlight() == 1 && client.sched.QueueLen(id) == 0
	})

	if err := old.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	next := reopenWithin(t, ctx, client, id, hold/2)
	if since := time.Since(heldAt); since >= hold {
		t.Fatalf("premise: the reopen took %v, past the %v the frame is held", since, hold)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the next stream: %v", err)
	}
	if err := next.Send(ctx, []byte("next stream's frame")); err != nil {
		t.Fatalf("send on the next stream: %v", err)
	}
	if got, err := accepted.Receive(ctx); err != nil || string(got) != "next stream's frame" {
		t.Fatalf("the next stream's peer read %q, %v", got, err)
	}
	if res := <-receiveAsync(ctx, accepted, 1500*time.Millisecond); res.err == nil {
		t.Fatalf("the next stream's peer read %q, which the ended stream sent", res.data)
	}
	waitSendWindowEmpty(t, next, "the next stream's frame acknowledged")
}

// TestNoiseStream_AProbeThePacerDefersStaysOffTheIDsNextStream: the write loop takes
// a TLP probe of a stream whose ACKs are lost, and the pacer defers it; between the
// write loop's taking it and its putting it back, the probe's stream is reset and the
// next stream opens under the same ID. The probe goes back only to the stream whose
// send window wrote it, and only while s.streams holds that stream (queueProbe), so the
// next stream's peer reads only what the next stream sent. A deferral that put the
// probe back under the frame's ID would hand it to the next stream's probe slot, and
// its peer would read the ended stream's frame as its own.
func TestNoiseStream_AProbeThePacerDefersStaysOffTheIDsNextStream(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	pacer := deferPacing(client)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const id = 964
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")
	toClient.setRule(func(f *aether.Frame) bool { return f.StreamID == id && f.Type == aether.TypeACK })

	if err := old.Send(ctx, []byte("ended stream's probe")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, "the ended stream's frame written", func() bool {
		f, _ := old.sendWindow.HighestWritten()
		return f != nil
	})

	type hookResult struct {
		probe bool
		next  aether.Stream
		err   error
	}
	ran := make(chan hookResult, 1)
	probesBefore := atomic.LoadUint64(&client.tlpFiresTotal)
	pacer.arm(200*time.Millisecond, func() {
		var r hookResult
		defer func() { ran <- r }()
		// The tick queues the probe before the write loop takes it, and counts it
		// just after: a frame the pacer is asked about once the count has moved is
		// that probe, the stream's one unacknowledged frame being younger than its RTO.
		deadline := time.Now().Add(time.Second)
		for atomic.LoadUint64(&client.tlpFiresTotal) == probesBefore && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		r.probe = atomic.LoadUint64(&client.tlpFiresTotal) > probesBefore
		toClient.setRule(nil)
		if r.err = old.Reset(aether.ResetCancel); r.err != nil {
			return
		}
		deadline = time.Now().Add(10 * time.Second)
		for {
			r.next, r.err = client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
			if r.err == nil || time.Now().After(deadline) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	var r hookResult
	select {
	case r = <-ran:
	case <-time.After(20 * time.Second):
		t.Fatal("the pacer was never asked about the probe")
	}
	if r.err != nil {
		t.Fatalf("reset and reopen: %v", r.err)
	}
	if !r.probe {
		t.Fatal("premise: the frame the pacer deferred was not the TLP probe")
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the next stream: %v", err)
	}
	if err := r.next.Send(ctx, []byte("next stream's frame")); err != nil {
		t.Fatalf("send on the next stream: %v", err)
	}
	if got, err := accepted.Receive(ctx); err != nil || string(got) != "next stream's frame" {
		t.Fatalf("the next stream's peer read %q, %v", got, err)
	}
	if res := <-receiveAsync(ctx, accepted, 1500*time.Millisecond); res.err == nil {
		t.Fatalf("the next stream's peer read %q, which the ended stream sent", res.data)
	}
}
