/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package congestion

import (
	"testing"
	"time"
)

// TestBBR_EntersProbeRTTWhenRTpropStale is the AE-M-05 regression. When BBR is
// in ProbeBW with an rtProp stamp older than the ProbeRTT interval, a single
// positive-rtt ACK must transition into ProbeRTT. Before the fix the ack-path
// rtProp refresh reset rtPropStamp to now, so runStateMachine's staleness
// re-check (now.Sub(rtPropStamp)) was ~0 and ProbeRTT was never entered.
func TestBBR_EntersProbeRTTWhenRTpropStale(t *testing.T) {
	b := NewBBRController()
	// Force ProbeBW with an rtProp stamp older than the ProbeRTT interval —
	// the exact precondition BBR uses to schedule a periodic ProbeRTT.
	b.state = bbrProbeBW
	b.btlBw = 1_000_000
	b.rtProp = 20 * time.Millisecond
	b.rtPropStamp = time.Now().Add(-bbrProbeRTTInterval - time.Second)

	// Warm SRTT is always > 0 in steady state — the real-world case that
	// AE-M-05 shows makes the ack-path refresh preempt the transition.
	b.OnAck(1400, 20*time.Millisecond)

	if got := b.State(); got != "probe-rtt" {
		t.Fatalf("BBR must enter ProbeRTT once rtProp is stale; got %s", got)
	}
}

// TestBBR_StaysProbeBWWhenRTpropFresh guards against a regression that fires
// ProbeRTT prematurely: a controller in ProbeBW with a just-set rtPropStamp
// and rtt >= rtProp must stay in ProbeBW.
func TestBBR_StaysProbeBWWhenRTpropFresh(t *testing.T) {
	b := NewBBRController()
	b.state = bbrProbeBW
	b.btlBw = 1_000_000
	b.rtProp = 20 * time.Millisecond
	b.rtPropStamp = time.Now() // fresh — not stale
	b.cycleStamp = time.Now()

	b.OnAck(1400, 20*time.Millisecond)

	if got := b.State(); got != "probe-bw" {
		t.Fatalf("BBR must stay in ProbeBW while rtProp is fresh; got %s", got)
	}
}

// TestBBR_OnCEIdempotentWithinRTT is the AE-M-06 regression. A burst of CE
// marks within one rtProp window must collapse to a single cwnd reduction, not
// one per ACK. Before the fix each OnCE applied another 0.85x cut.
func TestBBR_OnCEIdempotentWithinRTT(t *testing.T) {
	b := NewBBRController()

	// Grow cwnd and drive rtProp down to ~50ms (mirrors TestBBR_OnLossReducesCWND).
	for i := 0; i < 20; i++ {
		b.OnAck(1400, 50*time.Millisecond)
		time.Sleep(time.Millisecond)
	}
	cwndBefore := b.CWND()

	// First CE still applies the full 0.85x cut.
	b.OnCE(1400)
	cwndAfterOne := b.CWND()
	if cwndAfterOne >= cwndBefore {
		t.Fatalf("first CE must reduce cwnd: before=%d, after=%d", cwndBefore, cwndAfterOne)
	}

	// Back-to-back CE marks well within one rtProp window must NOT reduce again.
	for i := 0; i < 10; i++ {
		b.OnCE(1400)
	}
	cwndAfterMany := b.CWND()
	if cwndAfterMany != cwndAfterOne {
		t.Fatalf("CE burst within one RTT must collapse to a single reduction: afterOne=%d, afterMany=%d", cwndAfterOne, cwndAfterMany)
	}

	// A CE in a new RTT window re-arms and reduces again.
	time.Sleep(60 * time.Millisecond)
	b.OnCE(1400)
	if got := b.CWND(); got >= cwndAfterMany {
		t.Fatalf("CE in a new RTT window must reduce again: afterMany=%d, afterNewWindow=%d", cwndAfterMany, got)
	}
}

// TestBBRDegradedOnAck_TightLoopDoesNotInflateBandwidth is the AE-M-07
// regression. When the adapter drives the degraded OnAck path once per acked
// nil-sample entry in a tight loop, the sub-microsecond inter-call gaps must
// not inject spurious multi-GB/s delivery-rate samples into the bandwidth
// filter. Before the fix a single 1400-byte packet over a sub-microsecond gap
// yielded ~1e10 B/s, pinning btlBwFilter.max and blasting cwnd/pacing.
func TestBBRDegradedOnAck_TightLoopDoesNotInflateBandwidth(t *testing.T) {
	b := NewBBRController()
	// Simulate one composite-ACK handler acking a burst of nil-sample entries:
	// the adapter calls OnAck once per entry with no real time between calls.
	// All in-loop gaps are sub-millisecond, below bbrMinSampleInterval, so no
	// near-zero-interval sample may reach the filter.
	for i := 0; i < 128; i++ {
		b.OnAck(1400, 20*time.Millisecond)
	}
	// Primary assertion: btlBw must not be pinned by a spurious sample. A
	// 1400-byte packet over a sub-microsecond gap is ~1e10 B/s; without the
	// fix btlBwFilter.max() pins near there. With the fix it stays ~0.
	const saneMax = 1e9 // 1 GB/s
	if b.btlBw > saneMax {
		t.Fatalf("AE-M-07: tight-loop OnAck inflated btlBw to %.3e B/s (near-zero-interval sample leaked into filter)", b.btlBw)
	}
	// Corroborating assertion: raw pacingRate (startup = btlBw*bbrStartupGain)
	// must not reach the 10 Gbps clamp; without the fix it is ~2.9e10 >= MaxPacingRate.
	if pr := b.PacingRate(); pr >= MaxPacingRate {
		t.Fatalf("AE-M-07: pacingRate reached MaxPacingRate clamp (%.3e) from a spurious sample", pr)
	}
	// Regression guard: a genuinely-spaced ACK still yields a real, bounded sample.
	time.Sleep(2 * time.Millisecond)
	b.OnAck(1400, 20*time.Millisecond)
	if b.btlBw > saneMax {
		t.Fatalf("AE-M-07: real-interval sample unexpectedly huge: %.3e B/s", b.btlBw)
	}
}
