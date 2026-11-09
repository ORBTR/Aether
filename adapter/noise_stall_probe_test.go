/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/quality"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// stallPlan is a plan short enough to run through: probeStalled reads nothing else.
func stallPlan() quality.KeepalivePlan {
	return quality.KeepalivePlan{Strikes: 4, ProbeTimeout: 40 * time.Millisecond, RetryGap: 5 * time.Millisecond}
}

func stallSession() *NoiseSession {
	return &NoiseSession{BaseSession: aether.NewBaseSession("vl1_stall_local", "vl1_stall_remote", aether.ProtoNoise)}
}

// TestProbeStalled_ReturnsAtTheFirstAnswer: probing stops at the first answered ping,
// and no later ping goes out.
func TestProbeStalled_ReturnsAtTheFirstAnswer(t *testing.T) {
	calls := 0
	got := stallSession().probeStalled(stallPlan(), func(context.Context) (time.Duration, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("no answer")
		}
		return time.Millisecond, nil
	})
	if !got.answered || got.closed || got.attempts != 3 || calls != 3 || got.err != nil {
		t.Fatalf("got %+v after %d pings, want answered at the third", got, calls)
	}
}

// TestProbeStalled_TakesThePlansProbesAndNumbers: a path that answers nothing is probed
// Strikes times, each ping under the plan's ProbeTimeout and the pings RetryGap apart,
// and the last error is what the caller logs.
func TestProbeStalled_TakesThePlansProbesAndNumbers(t *testing.T) {
	plan := stallPlan()
	lastErr := errors.New("the last answer")
	var budgets []time.Duration
	start := time.Now()
	got := stallSession().probeStalled(plan, func(ctx context.Context) (time.Duration, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("a stall probe with no deadline")
		}
		budgets = append(budgets, time.Until(deadline))
		return 0, lastErr
	})
	elapsed := time.Since(start)
	if got.answered || got.closed || got.attempts != plan.Strikes || !errors.Is(got.err, lastErr) {
		t.Fatalf("got %+v, want %d unanswered probes ending in the last error", got, plan.Strikes)
	}
	if len(budgets) != plan.Strikes {
		t.Fatalf("%d pings, want %d", len(budgets), plan.Strikes)
	}
	for i, b := range budgets {
		if b <= 0 || b > plan.ProbeTimeout {
			t.Fatalf("ping %d's budget %v, want at most the plan's %v", i, b, plan.ProbeTimeout)
		}
	}
	if least := time.Duration(plan.Strikes-1) * plan.RetryGap; elapsed < least {
		t.Fatalf("%d probes took %v, want at least the plan's gaps, %v", plan.Strikes, elapsed, least)
	}
}

// TestProbeStalled_ACloseDuringAGapEndsIt: a session another path closes between probes
// ends the probing with closed set and sends no further ping.
func TestProbeStalled_ACloseDuringAGapEndsIt(t *testing.T) {
	s := stallSession()
	plan := stallPlan()
	plan.RetryGap = time.Minute
	calls := 0
	got := s.probeStalled(plan, func(context.Context) (time.Duration, error) {
		calls++
		s.SignalClose()
		return 0, errors.New("no answer")
	})
	if !got.closed || got.answered || calls != 1 {
		t.Fatalf("got %+v after %d pings, want closed after the first", got, calls)
	}
}

// TestAckDelayBound_IsThePeersMaxAckDelay: the bound is what the peer advertised, and
// without an advertisement the longest this build's ACK engine holds an ACK.
func TestAckDelayBound_IsThePeersMaxAckDelay(t *testing.T) {
	s := &NoiseSession{}
	if got, want := s.ackDelayBound(), reliability.DefaultACKPolicy().MaxDelay; got != want {
		t.Fatalf("with nothing advertised: %v, want %v", got, want)
	}
	s.peerMaxAckDelay = 40 * time.Millisecond
	if got := s.ackDelayBound(); got != 40*time.Millisecond {
		t.Fatalf("with 40ms advertised: %v", got)
	}
}

// TestHandleACK_DelayPastTheBoundCountsAsPathTime: an ACK reporting more delay than the
// peer's bound takes only the bound off its RTT sample, so a peer that overstates its
// delay cannot talk SRTT down. The first frame seeds SRTT and min_rtt near 50 ms; the
// second took 200 ms and its ACK claims 100 ms of that, against a 25 ms bound. The
// estimator keeps the raw sample whenever taking the delay off would leave it under
// min_rtt (rtt.Estimator.UpdateWithDelay); 200 ms less the whole 100 ms claim stays well
// above min_rtt, so that guard never decides this sample and only the bound does.
func TestHandleACK_DelayPastTheBoundCountsAsPathTime(t *testing.T) {
	s := &NoiseSession{streams: make(map[uint64]*noiseStream)}
	s.SetCongestionController(congestion.NewCUBICController())
	s.sched = scheduler.NewScheduler()
	s.peerMaxAckDelay = 25 * time.Millisecond

	eng := reliability.NewEngine(reliability.EngineConfig{StreamID: 1, WindowSize: 64})
	st := &noiseStream{
		streamID:    1,
		session:     s,
		sendWindow:  eng.SendWin,
		retransmitQ: eng.RetransmitQ,
		rtt:         eng.RTT,
		tlp:         congestion.NewTLP(0),
		rack:        congestion.NewRACK(eng.RTT.SRTT()),
	}
	s.streams[1] = st

	ackAfter := func(age, claimed time.Duration) {
		frame := &aether.Frame{Type: aether.TypeDATA, StreamID: 1}
		seq := st.sendWindow.Add(frame)
		st.sendWindow.MarkWritten(frame, 64, time.Now().Add(-age), nil)
		units := claimed / time.Microsecond / aether.AckDelayGranularity
		payload := aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: seq, AckDelay: uint16(units)})
		s.handleACK(&aether.Frame{Type: aether.TypeACK, StreamID: 1, Length: uint32(len(payload)), Payload: payload})
	}
	ackAfter(50*time.Millisecond, 0)
	seeded := st.rtt.SRTT()
	if seeded < 50*time.Millisecond {
		t.Fatalf("premise wrong: the first sample left SRTT at %v", seeded)
	}
	ackAfter(200*time.Millisecond, 100*time.Millisecond)
	// 7/8 of the old SRTT and 1/8 of a sample of at least 200-25 ms.
	want := seeded*7/8 + 175*time.Millisecond/8
	if got := st.rtt.SRTT(); got < want {
		t.Fatalf("SRTT %v after the overstated ACK, want at least %v: the delay past the bound came off the sample", got, want)
	}
}
