/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package multipath

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// budgetSession records the budget each Ping is given and answers none.
type budgetSession struct {
	*fakeSession
	budget chan time.Duration
}

func (b *budgetSession) Ping(ctx context.Context) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, errors.New("a probe with no deadline")
	}
	b.budget <- time.Until(deadline)
	return 0, errors.New("no answer")
}

// seededBudgetSession is a session whose estimator has measured rtt eight times, so its
// keepalive plan is past the warmup floor and follows the path.
func seededBudgetSession(remote string, rtt time.Duration) *budgetSession {
	f := newFakeSession(aether.ProtoNoise, 0, 0)
	f.remoteID = aether.NodeID(remote)
	for seq := uint32(1); seq <= 8; seq++ {
		f.hm.RecordPingSent(seq)
		f.hm.RecordPongRecv(seq, time.Now().Add(-rtt))
	}
	return &budgetSession{fakeSession: f, budget: make(chan time.Duration, 16)}
}

// TestProbeNonPrimary_ThePingBudgetIsThePathsPlan: each standby path's probe waits the
// ProbeTimeout its own measurements give, so a slow path is not failed on a fast path's
// number.
func TestProbeNonPrimary_ThePingBudgetIsThePathsPlan(t *testing.T) {
	fast := seededBudgetSession("fast", 2*time.Millisecond)
	slow := seededBudgetSession("slow", 2*time.Second)
	wantFast := aether.KeepalivePlanFor(fast).ProbeTimeout
	wantSlow := aether.KeepalivePlanFor(slow).ProbeTimeout
	if wantSlow <= wantFast {
		t.Fatalf("premise wrong: plans %v and %v do not differ", wantFast, wantSlow)
	}

	m := NewManager()
	m.AddPath(newFakeSession(aether.ProtoNoise, 0, 0), aether.ProtoNoise, 100)
	m.AddPath(fast, aether.ProtoNoise, 50)
	m.AddPath(slow, aether.ProtoNoise, 50)
	m.probeNonPrimary(context.Background())

	for name, c := range map[string]struct {
		s    *budgetSession
		want time.Duration
	}{"fast": {fast, wantFast}, "slow": {slow, wantSlow}} {
		select {
		case got := <-c.s.budget:
			if got > c.want || got < c.want-c.want/4 {
				t.Fatalf("%s path's ping budget %v, want its plan's %v", name, got, c.want)
			}
		default:
			t.Fatalf("the %s path was not probed", name)
		}
	}
}
