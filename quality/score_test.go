package quality

import (
	"testing"
	"time"
)

func TestRouteClass_ClassifyRegions(t *testing.T) {
	tests := []struct {
		name           string
		local, remote  string
		expectedClass  RouteClass
		expectedString string
	}{
		{"same-region", "syd", "syd", RouteSameRegion, "same-region"},
		{"cross-region NA", "iad", "lax", RouteCrossRegion, "cross-region"},
		{"inter-continental NA→OC", "iad", "syd", RouteInterContinental, "inter-continental"},
		{"inter-continental EU→NA", "fra", "iad", RouteInterContinental, "inter-continental"},
		{"unknown empty local", "", "syd", RouteUnknown, "unknown"},
		{"unknown bogus region", "xyz", "syd", RouteUnknown, "unknown"},
		{"case-insensitive", "SYD", "syd", RouteSameRegion, "same-region"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRegions(tc.local, tc.remote)
			if got != tc.expectedClass {
				t.Errorf("ClassifyRegions(%q, %q) = %v, want %v", tc.local, tc.remote, got, tc.expectedClass)
			}
			if got.String() != tc.expectedString {
				t.Errorf("String() = %q, want %q", got.String(), tc.expectedString)
			}
		})
	}
}

func TestRouteClass_ExpectedRTTBands(t *testing.T) {
	if RouteSameRegion.ExpectedRTT() >= RouteCrossRegion.ExpectedRTT() {
		t.Error("same-region expected RTT should be lower than cross-region")
	}
	if RouteCrossRegion.ExpectedRTT() >= RouteInterContinental.ExpectedRTT() {
		t.Error("cross-region expected RTT should be lower than inter-continental")
	}
	if RouteSameRegion.AcceptableRTT() <= RouteSameRegion.ExpectedRTT() {
		t.Error("acceptable RTT should exceed expected RTT")
	}
}

func TestComputeBaseline_HealthySameRegion(t *testing.T) {
	in := Inputs{
		Class:               RouteSameRegion,
		SRTT:                4 * time.Millisecond,
		RTTVar:              500 * time.Microsecond,
		BaselineRTT:         4 * time.Millisecond,
		LossPermille:        0,
		FramesRecv:          1000,
		Reorders:            0,
		BytesPerSec:         500_000,
		ConsecutiveFailures: 0,
		Reliability:         1.0,
		Stability:           1.0,
		Age:                 5 * time.Minute,
	}
	score := Compute(in, DefaultWeights)
	if score.Aggregate < 0.85 {
		t.Errorf("healthy same-region path scored %.3f, want > 0.85", score.Aggregate)
	}
	if !score.IsHealthy() {
		t.Error("healthy path should pass IsHealthy")
	}
	if !score.IsAlive() {
		t.Error("healthy path should pass IsAlive")
	}
}

func TestCompute_HealthyCrossRegion_NotPunished(t *testing.T) {
	// The whole point of route-class normalization: a 250 ms cross-
	// region path should score similarly to a 5 ms same-region path
	// when both are healthy for their kind.
	sameRegion := Inputs{
		Class:       RouteSameRegion,
		SRTT:        5 * time.Millisecond,
		BaselineRTT: 5 * time.Millisecond,
		FramesRecv:  1000,
		BytesPerSec: 500_000,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         5 * time.Minute,
	}
	crossRegion := Inputs{
		Class:       RouteInterContinental,
		SRTT:        250 * time.Millisecond,
		BaselineRTT: 250 * time.Millisecond,
		FramesRecv:  1000,
		BytesPerSec: 256_000,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         5 * time.Minute,
	}
	srSame := Compute(sameRegion, DefaultWeights)
	srCross := Compute(crossRegion, DefaultWeights)
	if srCross.Aggregate < 0.7 {
		t.Errorf("healthy inter-continental path scored %.3f, want > 0.7", srCross.Aggregate)
	}
	// Both should be healthy; the ratio shouldn't be lopsided.
	if srSame.Aggregate-srCross.Aggregate > 0.2 {
		t.Errorf("same-region (%.3f) and cross-region (%.3f) scores differ too much; should normalize",
			srSame.Aggregate, srCross.Aggregate)
	}
}

func TestCompute_NewSession_AgeGrace(t *testing.T) {
	in := Inputs{
		Class:       RouteSameRegion,
		SRTT:        4 * time.Millisecond,
		BaselineRTT: 4 * time.Millisecond,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         2 * time.Second,
	}
	score := Compute(in, DefaultWeights)
	if score.Aggregate != 0 {
		t.Errorf("session younger than 5 s should score 0 (AgeGrace), got %.3f", score.Aggregate)
	}
}

func TestCompute_DegradesWithLoss(t *testing.T) {
	base := Inputs{
		Class:       RouteSameRegion,
		SRTT:        4 * time.Millisecond,
		BaselineRTT: 4 * time.Millisecond,
		FramesRecv:  1000,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         5 * time.Minute,
	}
	clean := Compute(base, DefaultWeights)

	lossy := base
	lossy.LossPermille = 50
	withLoss := Compute(lossy, DefaultWeights)

	if withLoss.Aggregate >= clean.Aggregate {
		t.Errorf("lossy path (%.3f) should score lower than clean path (%.3f)",
			withLoss.Aggregate, clean.Aggregate)
	}
}

func TestCompute_FailurePenalty(t *testing.T) {
	base := Inputs{
		Class:       RouteSameRegion,
		SRTT:        4 * time.Millisecond,
		BaselineRTT: 4 * time.Millisecond,
		FramesRecv:  1000,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         5 * time.Minute,
	}
	clean := Compute(base, DefaultWeights)

	withFailures := base
	withFailures.ConsecutiveFailures = 5
	failing := Compute(withFailures, DefaultWeights)

	if failing.Aggregate >= clean.Aggregate*0.3 {
		t.Errorf("path with 5 consecutive failures (%.3f) should score < 30%% of clean (%.3f)",
			failing.Aggregate, clean.Aggregate)
	}
}

func TestCompute_RTTTrend_RisingPenalized(t *testing.T) {
	stable := Inputs{
		Class:       RouteSameRegion,
		SRTT:        5 * time.Millisecond,
		BaselineRTT: 5 * time.Millisecond,
		FramesRecv:  1000,
		Reliability: 1.0,
		Stability:   1.0,
		Age:         5 * time.Minute,
	}
	rising := stable
	rising.SRTT = 15 * time.Millisecond // 3× baseline

	stableScore := Compute(stable, DefaultWeights)
	risingScore := Compute(rising, DefaultWeights)

	if risingScore.Components.RTTTrend >= stableScore.Components.RTTTrend {
		t.Errorf("rising RTT should reduce trend component (rising=%.3f, stable=%.3f)",
			risingScore.Components.RTTTrend, stableScore.Components.RTTTrend)
	}
}

func TestDispatchRank_RegionAffinity(t *testing.T) {
	// Two equally healthy paths, one same-region one inter-continental.
	// Same-region should rank higher.
	same := Score{
		Aggregate:  0.8,
		Class:      RouteSameRegion,
		Components: Components{RTT: 0.95, Throughput: 0.9, Stability: 0.95},
	}
	cross := Score{
		Aggregate:  0.8,
		Class:      RouteInterContinental,
		Components: Components{RTT: 0.95, Throughput: 0.9, Stability: 0.95},
	}
	rSame := DispatchRank(same, OpDefault)
	rCross := DispatchRank(cross, OpDefault)
	if rSame <= rCross {
		t.Errorf("same-region rank (%.3f) should exceed inter-continental (%.3f) for OpDefault",
			rSame, rCross)
	}
}

func TestDispatchRank_OpClassWeighting(t *testing.T) {
	// Two paths with same aggregate but different component profiles:
	// one fast-and-low-throughput, one slow-and-high-throughput.
	fast := Score{
		Aggregate:  0.7,
		Class:      RouteSameRegion,
		Components: Components{RTT: 0.95, Throughput: 0.4, Stability: 0.7},
	}
	bulky := Score{
		Aggregate:  0.7,
		Class:      RouteSameRegion,
		Components: Components{RTT: 0.5, Throughput: 0.95, Stability: 0.7},
	}
	if DispatchRank(fast, OpLatencySensitive) <= DispatchRank(bulky, OpLatencySensitive) {
		t.Error("OpLatencySensitive should prefer the fast path")
	}
	if DispatchRank(bulky, OpBulkTransfer) <= DispatchRank(fast, OpBulkTransfer) {
		t.Error("OpBulkTransfer should prefer the bulky path")
	}
}

func TestTracker_BaselineRTTConverges(t *testing.T) {
	tr := NewTracker()
	key := Key("peer1", "noise-udp")
	for i := 0; i < 100; i++ {
		tr.UpdateRTT(key, 50*time.Millisecond)
	}
	got := tr.BaselineRTT(key)
	// EMA with α=0.05 over 100 samples of 50ms — should converge close.
	if got < 45*time.Millisecond || got > 55*time.Millisecond {
		t.Errorf("baseline didn't converge to 50ms: got %v", got)
	}
}

func TestTracker_FailuresAccumulate(t *testing.T) {
	tr := NewTracker()
	key := Key("peer1", "ws")

	tr.RecordClose(key, false) // error close
	tr.RecordClose(key, false)
	tr.RecordClose(key, false)
	if tr.ConsecutiveFailures(key) != 3 {
		t.Errorf("expected 3 consecutive failures, got %d", tr.ConsecutiveFailures(key))
	}
	if tr.Reliability(key) >= 1.0 {
		t.Errorf("reliability should drop after error closes, got %.3f", tr.Reliability(key))
	}

	tr.RecordClose(key, true) // clean close resets consecutive
	if tr.ConsecutiveFailures(key) != 0 {
		t.Errorf("clean close should reset consecutive failures, got %d", tr.ConsecutiveFailures(key))
	}
}

func TestTracker_StabilityTracksScoreVariance(t *testing.T) {
	tr := NewTracker()
	key := Key("peer1", "ws")
	// Stable score sequence — stability should stay high.
	for i := 0; i < 20; i++ {
		tr.RecordScore(key, 0.8)
	}
	stable := tr.Stability(key)
	if stable < 0.8 {
		t.Errorf("stable score sequence should yield stability > 0.8, got %.3f", stable)
	}

	// Bouncy sequence — stability should drop.
	tr2 := NewTracker()
	for i := 0; i < 20; i++ {
		s := 0.3
		if i%2 == 0 {
			s = 0.9
		}
		tr2.RecordScore(key, s)
	}
	bouncy := tr2.Stability(key)
	if bouncy >= stable {
		t.Errorf("bouncy score sequence should drop stability below stable (stable=%.3f, bouncy=%.3f)",
			stable, bouncy)
	}
}
