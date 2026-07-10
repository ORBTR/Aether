package quality

import (
	"math"
	"time"
)

// Components is the eight-dimensional decomposition of a session's quality
// score. Each component is in [0, 1] where 1 = perfect, 0 = useless.
// The aggregate Score is computed by Compute() as a weighted geometric
// mean of these.
//
// Storing components separately (rather than just the aggregate) lets
// observability surfaces explain *why* a score is what it is and lets the
// dispatch layer apply context-specific weighting (e.g., latency-sensitive
// dispatches care more about RTT, bulk transfers care more about
// throughput).
type Components struct {
	// RTT measures how close the session's smoothed RTT is to the
	// expected band for its RouteClass. Sigmoidal — degrades smoothly
	// past AcceptableRTT rather than cliffing at 3× expected.
	RTT float64

	// RTTTrend is the rate-of-change adjustment. A path whose RTT is
	// rising scores worse than one with the same RTT that's stable.
	// Acts as an early-warning signal for impending congestion.
	RTTTrend float64

	// Loss is the recent packet-loss rate, normalized so 1 = no loss
	// and ~0.1 = severe loss. Exponential decay so a small amount of
	// loss is tolerated without dominating the score.
	Loss float64

	// Jitter is RTT variance normalized against SRTT. Stable paths
	// (low RTTVar / SRTT) score 1; volatile ones (e.g. mobile, satellite)
	// drop. Set conservatively so cellular paths don't score 0.
	Jitter float64

	// Reorder is the rate of out-of-order frames. UDP paths in lossy
	// networks reorder; sustained reordering is a signal of MTU/path
	// issues. Less weight than RTT/loss because reorder is recoverable.
	Reorder float64

	// Throughput is observed bytes/sec normalized against the route
	// class's expected ceiling. Low throughput on a high-RTT path is
	// expected and doesn't penalize; low throughput on a low-RTT path
	// suggests something else is constraining the connection.
	Throughput float64

	// Reliability is 1 − close-error-rate over recent session lifetime.
	// Sessions that frequently close with errors (vs clean GoAway) on
	// the same (peer, transport) pair score lower here.
	Reliability float64

	// Stability is 1 − recent score variance. A path whose own score
	// is bouncing around scores lower than one with a steady (even if
	// lower) score. Discourages flap-prone paths from being chosen
	// over consistently mediocre but stable ones.
	Stability float64

	// FailurePenalty is a multiplicative factor in [0, 1]. Severe
	// recent failures (consecutive close-with-error events on this
	// peer-transport pair) drive this toward 0, effectively black-
	// listing the path. Replaces the boolean ProtoIsDead/
	// sticky-bad-path memory with a continuous decay.
	FailurePenalty float64

	// AgeGrace is a [0, 1] factor that ramps from 0 → 1 over the
	// session's first ~30 s. Prevents a brand-new session from being
	// scored low because it hasn't had enough time to accumulate
	// throughput/reliability signals.
	AgeGrace float64
}

// Weights tunes how much each component contributes to the geometric
// mean. Higher weight = bigger pull toward 0 if the component is low.
// Defaults are calibrated for the ORBTR mesh's workload (gossip-
// heavy, RPC-medium, bulk-transfer-light); applications that drive a
// lot of bulk traffic should override Throughput up.
type Weights struct {
	RTT         float64
	RTTTrend    float64
	Loss        float64
	Jitter      float64
	Reorder     float64
	Throughput  float64
	Reliability float64
	Stability   float64
}

// DefaultWeights are the production starting point. Tuned so RTT and
// Loss dominate (they're the most visible to end-users), Reliability
// and Stability matter (avoid flap-prone paths), and Reorder /
// Throughput are signals but not gates.
var DefaultWeights = Weights{
	RTT:         3.0, // dominant — latency is what users feel
	RTTTrend:    1.0, // early-warning of congestion
	Loss:        2.5, // dominant — drives RPC retry storms
	Jitter:      1.0, // matters for streaming/RPC tail latency
	Reorder:     0.5, // recoverable, light weight
	Throughput:  0.5, // contextual; bulk callers can up-weight
	Reliability: 2.0, // discourages flap-prone paths
	Stability:   1.5, // discourages oscillating-score paths
}

// score combines the components via a weighted geometric mean, with
// FailurePenalty and AgeGrace as multiplicative gates.
//
//	GM = product(Component_i ^ weight_i) ^ (1 / sum(weights))
//	Score = GM × FailurePenalty × AgeGrace
//
// Geometric mean is used (rather than arithmetic) so a single near-zero
// component pulls the aggregate down — a path can't compensate for
// terrible RTT by being lossless. Multiplicative gates make
// FailurePenalty and AgeGrace able to override the geometric mean
// entirely (e.g. brand-new sessions read as 0 until their grace period
// elapses).
func (c Components) score(w Weights) float64 {
	weights := []float64{
		w.RTT, w.RTTTrend, w.Loss, w.Jitter,
		w.Reorder, w.Throughput, w.Reliability, w.Stability,
	}
	values := []float64{
		c.RTT, c.RTTTrend, c.Loss, c.Jitter,
		c.Reorder, c.Throughput, c.Reliability, c.Stability,
	}

	var weightSum float64
	var logSum float64
	for i, v := range values {
		if weights[i] <= 0 {
			continue
		}
		v = clamp01(v)
		// log(0) is -Inf; clamp values to a small floor so the
		// geometric mean stays meaningful for legitimately-bad paths.
		if v < 1e-6 {
			v = 1e-6
		}
		weightSum += weights[i]
		logSum += weights[i] * math.Log(v)
	}
	if weightSum == 0 {
		return 0
	}
	gm := math.Exp(logSum / weightSum)
	return clamp01(gm) * clamp01(c.FailurePenalty) * clamp01(c.AgeGrace)
}

// rttHealth maps measured SRTT against the route class's expected band
// using a logistic curve. ExpectedRTT scores 1.0; AcceptableRTT scores
// ~0.5; 2×AcceptableRTT scores ~0.1. The curve is asymmetric — paths
// faster than expected score 1.0 (no upside bonus, just no penalty).
func rttHealth(srtt time.Duration, class RouteClass) float64 {
	if srtt <= 0 {
		// No measurement yet — give benefit of the doubt; AgeGrace
		// will gate the overall score until enough data is collected.
		return 1.0
	}
	expected := class.ExpectedRTT()
	acceptable := class.AcceptableRTT()
	if srtt <= expected {
		return 1.0
	}
	// Logistic centered at AcceptableRTT, slope set by (acceptable -
	// expected). At srtt=acceptable → 0.5; at srtt=expected → ~1.0;
	// at srtt=2×acceptable → ~0.1.
	x := float64(srtt-acceptable) / float64(acceptable-expected)
	return 1.0 / (1.0 + math.Exp(x))
}

// rttTrendHealth penalizes a path whose RTT is climbing relative to its
// own short-term average. baselineRTT is the path's own SRTT EMA; a
// rising current RTT shifts this below 1.
func rttTrendHealth(srtt, baselineRTT time.Duration) float64 {
	if baselineRTT <= 0 || srtt <= 0 {
		return 1.0
	}
	if srtt <= baselineRTT {
		return 1.0 // RTT improving or stable — full credit
	}
	// Trend is the relative rise. Logistic so a 2× rise scores ~0.5,
	// a 4× rise scores ~0.1.
	rise := float64(srtt-baselineRTT) / float64(baselineRTT)
	return 1.0 / (1.0 + math.Exp(2*(rise-1)))
}

// lossHealth maps a permille loss rate (0–1000) to [0, 1] via
// exponential decay. 0‰ scores 1; 5‰ scores ~0.78; 50‰ scores ~0.08.
// Tolerates a small amount of loss without crashing the score.
func lossHealth(lossPermille int) float64 {
	if lossPermille <= 0 {
		return 1.0
	}
	return math.Exp(-float64(lossPermille) / 25.0)
}

// jitterHealth normalizes RTTVar against SRTT. A path with RTTVar =
// 50 % of SRTT is borderline (~0.5); RTTVar < 20 % of SRTT scores ~1.0.
// Calibrated so cellular/satellite paths (typical RTTVar ≈ 30–40 % of
// SRTT) score around 0.7–0.8 — useful but not preferred when alternatives
// exist.
func jitterHealth(srtt, rttvar time.Duration) float64 {
	if srtt <= 0 {
		return 1.0
	}
	if rttvar <= 0 {
		return 1.0
	}
	ratio := float64(rttvar) / float64(srtt)
	if ratio <= 0.2 {
		return 1.0
	}
	return math.Exp(-(ratio - 0.2) * 2)
}

// reorderHealth maps reorder count to [0, 1]. Computed against frame
// volume so a quiet path with 5 reorders doesn't get punished the same
// way as a busy path with 5 reorders.
func reorderHealth(reorders, framesRecv int64) float64 {
	if framesRecv <= 0 {
		return 1.0
	}
	rate := float64(reorders) / float64(framesRecv)
	if rate <= 0.001 {
		return 1.0
	}
	return math.Exp(-rate * 50)
}

// throughputHealth maps observed bytes/sec against an expected band per
// route class. Sigmoidal so very-low-throughput paths score lower but
// don't zero out (a quiet but healthy path is fine).
func throughputHealth(bps float64, class RouteClass) float64 {
	target := expectedThroughput(class)
	if target <= 0 {
		return 1.0
	}
	if bps <= 0 {
		// No observation yet — defer to AgeGrace via the aggregate.
		return 1.0
	}
	ratio := bps / target
	// Logistic centered at 0.5 × target.
	return 1.0 / (1.0 + math.Exp(-4*(ratio-0.5)))
}

// expectedThroughput returns a rough target bytes/sec for the route
// class. These numbers are deliberately low — even constrained mobile
// connections meet them. The throughput component is meant to flag
// pathologically constrained paths, not penalize quiet ones.
func expectedThroughput(class RouteClass) float64 {
	switch class {
	case RouteSameRegion:
		return 1024 * 1024 // 1 MB/s
	case RouteCrossRegion:
		return 512 * 1024 // 512 KB/s
	case RouteInterContinental, RouteUnknown:
		return 256 * 1024 // 256 KB/s
	default:
		return 256 * 1024
	}
}

// ageGrace ramps from 0 → 1 over the session's first 30 s. Sessions
// younger than 5 s score 0 (effectively unselectable for dispatch);
// at 30 s the grace period is over and the regular score takes over.
func ageGrace(age time.Duration) float64 {
	if age < 5*time.Second {
		return 0.0
	}
	if age >= 30*time.Second {
		return 1.0
	}
	return float64(age-5*time.Second) / float64(25*time.Second)
}

// failurePenalty exponentially decays based on consecutive recent
// close-with-error events. 0 events → 1.0; 1 event → ~0.6; 3 events →
// ~0.2; 5 events → ~0.08. Mirrors what sticky-bad-path memory used
// to do, but as a continuous factor rather than a boolean blacklist.
func failurePenalty(consecutiveFailures int) float64 {
	if consecutiveFailures <= 0 {
		return 1.0
	}
	return math.Exp(-float64(consecutiveFailures) / 2.0)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
