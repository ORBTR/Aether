/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether_test

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/quality"
)

// TestTheKeepalivePlanFollowsTheSessionsLossAndStability: probes lost on a path that then
// answers again are counted by RunKeepalive, and the plan KeepalivePlanFor reads from the
// session follows the loss and the instability its monitor measured: a lossy session is
// planned more strikes and an unstable one a longer probe timeout.
func TestTheKeepalivePlanFollowsTheSessionsLossAndStability(t *testing.T) {
	if testing.Short() {
		t.Skip("two warm-up probe timeouts of a lost path take about twelve seconds")
	}
	_, listener, relay := relayedTCPPair(t, aether.DefaultSessionOptions())
	done, stop := runKeepalive(t, listener)
	h := listener.Health()

	wait := func(what string, until time.Duration, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(until)
		for !ok() {
			select {
			case err := <-done:
				t.Fatalf("RunKeepalive returned %v while waiting for %s", err, what)
			case <-time.After(20 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %s within %s", what, until)
			}
		}
	}
	plan := aether.KeepalivePlanFor(listener)
	wait("first answered probe", 2*plan.Interval, func() bool { return h.SampleCount() >= 1 })
	if got := h.ProbeLoss(); got != 0 {
		t.Fatalf("probe loss %v before any probe was lost", got)
	}

	// Two probes lost: the relay holds both until it thaws, then the third is answered.
	relay.frozen.Store(true)
	time.Sleep(plan.Interval + 2*plan.ProbeTimeout + plan.RetryGap/2)
	relay.frozen.Store(false)
	wait("loss counted after the path answered again", 2*plan.Interval+plan.ProbeTimeout, func() bool { return h.ProbeLoss() > 0 })

	got := aether.KeepalivePlanFor(listener)
	want := quality.Keepalive(quality.KeepaliveInputs{
		SRTT: h.SRTT(), RTO: h.RTO(), Samples: h.SampleCount(), Loss: h.ProbeLoss(), Instability: h.Instability(),
	})
	if got != want {
		t.Errorf("KeepalivePlanFor = %+v, want the plan for the monitor's measurements %+v", got, want)
	}
	for range 30 {
		h.RecordKeepaliveAnswer(1)
	}
	if lossy := aether.KeepalivePlanFor(listener); lossy.Strikes <= plan.Strikes {
		t.Errorf("a session losing half its probes is planned %d strikes, no more than a clean one's %d", lossy.Strikes, plan.Strikes)
	}
	t.Logf("probe loss %.3f after two lost probes; instability %.3f", h.ProbeLoss(), h.Instability())

	// Round trips that jump between 50 ms and 250 ms read as unstable, and the plan's
	// probe timeout follows: the keepalive is stopped so its own probes do not take
	// these answers.
	stop()
	for i := range 20 {
		rtt := 50 * time.Millisecond
		if i%2 == 1 {
			rtt = 250 * time.Millisecond
		}
		seq := uint32(1000 + i)
		h.RecordPingSent(seq)
		h.RecordPongRecv(seq, time.Now().Add(-rtt))
	}
	steadyIn := quality.KeepaliveInputs{SRTT: h.SRTT(), RTO: h.RTO(), Samples: h.SampleCount(), Loss: h.ProbeLoss()}
	unstable := aether.KeepalivePlanFor(listener)
	if steady := quality.Keepalive(steadyIn); unstable.ProbeTimeout <= steady.ProbeTimeout {
		t.Errorf("a session whose round trips jump (instability %.3f) waits %s per probe, no longer than a steady one's %s",
			h.Instability(), unstable.ProbeTimeout, steady.ProbeTimeout)
	}
}
