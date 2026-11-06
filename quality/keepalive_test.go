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
	if got, want := Keepalive(KeepaliveInputs{SRTT: time.Hour, RTO: time.Hour, Samples: 100}).DeadPeerBound(), 109*time.Second; got != want {
		t.Errorf("the largest DeadPeerBound = %s, want %s", got, want)
	}
}
