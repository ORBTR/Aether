/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quality

import (
	"testing"
	"time"
)

// TestTheKeepalivePlanFollowsTheMeasurements: the plan is decided by the path's own
// measurements. A session with nothing measured takes the floors; a slower path waits
// longer between probes and per probe; a converged estimator earns the tighter probe
// floor; and every bound stays positive and capped however large the measurement.
func TestTheKeepalivePlanFollowsTheMeasurements(t *testing.T) {
	for _, tc := range []struct {
		name         string
		in           KeepaliveInputs
		interval     time.Duration
		probeTimeout time.Duration
	}{
		{"nothing measured", KeepaliveInputs{}, 5 * time.Second, 5 * time.Second},
		{"fast path warming up", KeepaliveInputs{SRTT: time.Millisecond, RTO: 200 * time.Millisecond, Samples: 3}, 5 * time.Second, 5 * time.Second},
		{"fast path converged", KeepaliveInputs{SRTT: time.Millisecond, RTO: 200 * time.Millisecond, Samples: 8}, 5 * time.Second, time.Second},
		{"cross-region converged", KeepaliveInputs{SRTT: 4 * time.Second, RTO: 2 * time.Second, Samples: 20}, 8 * time.Second, 8 * time.Second},
		{"satellite-class path", KeepaliveInputs{SRTT: 20 * time.Second, RTO: 30 * time.Second, Samples: 20}, 30 * time.Second, 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Keepalive(tc.in)
			if p.Interval != tc.interval || p.ProbeTimeout != tc.probeTimeout {
				t.Errorf("plan = interval %s probe %s, want %s and %s", p.Interval, p.ProbeTimeout, tc.interval, tc.probeTimeout)
			}
			if p.Strikes < 1 || p.RetryGap <= 0 {
				t.Errorf("plan = %d strikes, retry gap %s: a plan must end a silent session", p.Strikes, p.RetryGap)
			}
			if again := Keepalive(tc.in); again != p {
				t.Errorf("the same measurements gave %+v then %+v", p, again)
			}
		})
	}
}

// TestTheDeadPeerBoundIsTheProbeCycle states the bound the keepalive ends a silent
// session within, as RunKeepalive spends it: one interval to the probe that finds the
// peer silent, then every strike's probe timeout with the retry gap between them.
func TestTheDeadPeerBoundIsTheProbeCycle(t *testing.T) {
	p := KeepalivePlan{Interval: 5 * time.Second, ProbeTimeout: time.Second, Strikes: 5, RetryGap: time.Second}
	if got, want := p.Silence(), 9*time.Second; got != want {
		t.Errorf("Silence = %s, want %s", got, want)
	}
	if got, want := p.DeadPeerBound(), 14*time.Second; got != want {
		t.Errorf("DeadPeerBound = %s, want %s", got, want)
	}
	if got, want := Keepalive(KeepaliveInputs{}).DeadPeerBound(), 34*time.Second; got != want {
		t.Errorf("a new session's DeadPeerBound = %s, want %s", got, want)
	}
	slowest := KeepaliveInputs{SRTT: time.Hour, RTO: time.Hour, Samples: 100}
	if got, want := Keepalive(slowest).DeadPeerBound(), 109*time.Second; got != want {
		t.Errorf("the largest DeadPeerBound with no loss = %s, want %s", got, want)
	}

	// Loss raises Strikes, so the largest bound is taken over the range a session's
	// health.Monitor reports loss and instability in, 0 to 1, and over paths from a new
	// session to the slowest the clamps admit. It is the 30 s interval ceiling, then
	// keepaliveStrikesCeiling probes at the 15 s probe ceiling with a 1 s gap between each:
	// 30 + 10*15 + 9 = 189 s. RunKeepalive ends a silent session within its plan's
	// DeadPeerBound, so this is the longest any session holds a peer that stopped answering.
	const largestBound = 189 * time.Second
	var largest time.Duration
	var largestAt KeepaliveInputs
	for _, path := range []KeepaliveInputs{
		{},
		{SRTT: time.Millisecond, RTO: 200 * time.Millisecond, Samples: 8},
		{SRTT: 4 * time.Second, RTO: 2 * time.Second, Samples: 20},
		slowest,
	} {
		for step := 0; step <= 100; step++ {
			for _, instability := range []float64{0, 0.5, 1} {
				in := path
				in.Loss, in.Instability = float64(step)/100, instability
				bound := Keepalive(in).DeadPeerBound()
				if bound > largestBound {
					t.Errorf("inputs %+v give DeadPeerBound %s, past the largest %s", in, bound, largestBound)
				}
				if bound > largest {
					largest, largestAt = bound, in
				}
			}
		}
	}
	if largest != largestBound {
		t.Errorf("the largest DeadPeerBound over the loss range = %s (at %+v), want %s", largest, largestAt, largestBound)
	}
}

// TestTheKeepalivePlanFollowsLoss: two sessions with the same round trips get plans that
// differ only by their probe loss. A path that loses a quarter of its probes or fewer
// keeps 5 strikes; a lossier one is held to more, so a healthy peer losing that share of
// its probes is let go with chance at most 1 in 1000, and never more than 10.
func TestTheKeepalivePlanFollowsLoss(t *testing.T) {
	rtt := KeepaliveInputs{SRTT: 40 * time.Millisecond, RTO: 300 * time.Millisecond, Samples: 20}
	steady := Keepalive(rtt)
	for _, tc := range []struct {
		loss    float64
		strikes int
	}{{0, 5}, {0.25, 5}, {0.3, 6}, {0.5, 10}, {0.9, 10}, {1, 10}} {
		in := rtt
		in.Loss = tc.loss
		p := Keepalive(in)
		if p.Strikes != tc.strikes {
			t.Errorf("loss %.2f: %d strikes, want %d", tc.loss, p.Strikes, tc.strikes)
		}
		if p.Interval != steady.Interval || p.ProbeTimeout != steady.ProbeTimeout || p.RetryGap != steady.RetryGap {
			t.Errorf("loss %.2f moved more than the strikes: %+v against %+v", tc.loss, p, steady)
		}
	}
	lossy := rtt
	lossy.Loss = 0.5
	if Keepalive(lossy).DeadPeerBound() <= steady.DeadPeerBound() {
		t.Error("a lossy path's dead-peer bound is no longer than a clean one's")
	}
}

// TestTheKeepalivePlanFollowsStability: two converged sessions with the same SRTT and RTO
// get probe timeouts that differ by their instability: a path whose round trips jump
// waits up to twice as long for an answer, inside the same ceiling, and nothing else in
// the plan moves.
func TestTheKeepalivePlanFollowsStability(t *testing.T) {
	rtt := KeepaliveInputs{SRTT: 400 * time.Millisecond, RTO: time.Second, Samples: 20}
	for _, tc := range []struct {
		instability float64
		probe       time.Duration
	}{{0, 4 * time.Second}, {0.25, 5 * time.Second}, {0.5, 6 * time.Second}, {1, 8 * time.Second}, {3, 8 * time.Second}} {
		in := rtt
		in.Instability = tc.instability
		p := Keepalive(in)
		if p.ProbeTimeout != tc.probe {
			t.Errorf("instability %.2f: probe timeout %s, want %s", tc.instability, p.ProbeTimeout, tc.probe)
		}
		if p.Interval != Keepalive(rtt).Interval || p.Strikes != Keepalive(rtt).Strikes {
			t.Errorf("instability %.2f moved more than the probe timeout: %+v", tc.instability, p)
		}
	}
	slow := KeepaliveInputs{SRTT: 2 * time.Second, RTO: 3 * time.Second, Samples: 20, Instability: 1}
	if got := Keepalive(slow).ProbeTimeout; got != 15*time.Second {
		t.Errorf("an unstable slow path's probe timeout %s, want the 15 s ceiling", got)
	}
}
