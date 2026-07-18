/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package congestion

import (
	"math"
	"sync"
	"time"
)

const (
	// cubicBeta is the multiplicative decrease factor (RFC 8312).
	cubicBeta = 0.7

	// cubicC is the CUBIC scaling constant (RFC 8312).
	cubicC = 0.4

	// initialCWND is the initial congestion window (10 segments × 1400 bytes).
	initialCWND int64 = 14000

	// minCWND is the minimum congestion window (2 segments).
	minCWND int64 = 2800

	// maxCWND is the maximum congestion window (10 MB).
	maxCWND int64 = 10 * 1024 * 1024

	// defaultMSS is the assumed maximum segment size.
	defaultMSS int64 = 1400
)

type cubicState int

const (
	cubicSlowStart          cubicState = iota
	cubicCongestionAvoidance
	cubicFastRecovery
)

// CUBICController implements the CUBIC congestion control algorithm (RFC 8312)
// with Proportional Rate Reduction (RFC 6937) layered over fast recovery and
// an explicit "persistent-congestion exit" path used by the adapter when its
// probe-before-close confirms the path is alive.
//
// PRR replaces the previous "cwnd += ackedBytes*MSS/cwnd during fast
// recovery" growth, which over-shoots and produces bursty send patterns
// during recovery. PRR proportionally drains in-flight to the new
// ssthresh, which empirically performs better on bursty-loss paths and
// is what Linux's TCP stack has done since 3.2.
//
// Persistent-congestion exit: when the adapter's probe-before-close path
// (3 Pings within 3 s) succeeds, the path is provably alive, so the
// previous cumulative OnLoss reductions that drove cwnd to the floor
// were diagnosing transient loss as persistent congestion. ResetCWND()
// restores cwnd to initialCWND and exits fast recovery, breaking the
// deadlock where inFlight >= cwnd prevents any new sends and thus any
// new ACKs.
type CUBICController struct {
	mu       sync.Mutex
	cwnd     float64    // congestion window (bytes)
	ssthresh float64    // slow start threshold
	wMax     float64    // cwnd at last loss event
	tEpoch   time.Time  // start of current CUBIC epoch
	state    cubicState
	acked    int64      // bytes acked since last loss
	mss      int64      // maximum segment size (updated by PMTU discovery)

	// PRR (RFC 6937) accounting. Only consulted while state ==
	// cubicFastRecovery; reset on EnterRecovery and zero outside.
	prrDelivered int64 // cumulative bytes ACKed since recovery entry
	prrOut       int64 // cumulative bytes sent since recovery entry
	recoverFS    int64 // pipe size (in-flight bytes) at recovery entry
}

// NewCUBICController creates a CUBIC controller with initial window.
func NewCUBICController() *CUBICController {
	return &CUBICController{
		cwnd:     float64(initialCWND),
		ssthresh: float64(maxCWND), // no threshold initially → slow start
		state:    cubicSlowStart,
		mss:      defaultMSS,
	}
}

// SetMSS updates the maximum segment size (called by PMTU discovery).
func (c *CUBICController) SetMSS(mss int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mss > 0 {
		c.mss = int64(mss)
	}
}

// OnAck processes an acknowledgment. Adapter passes pipeBytes (current
// in-flight) so the recovery-phase PRR formula has the data it needs.
// Pass 0 for pipeBytes if unknown — fast recovery falls back to the
// pre-PRR per-ACK growth rule, preserving prior behaviour.
func (c *CUBICController) OnAck(ackedBytes int64, rtt time.Duration) {
	c.OnAckWithPipe(ackedBytes, rtt, 0)
}

// OnAckWithPipe is the PRR-aware variant. The adapter passes the current
// in-flight byte count so PRR can compute the proportional send budget
// per RFC 6937 §3.1.
func (c *CUBICController) OnAckWithPipe(ackedBytes int64, rtt time.Duration, pipeBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.acked += ackedBytes

	switch c.state {
	case cubicSlowStart:
		// Exponential growth: cwnd += ackedBytes
		c.cwnd += float64(ackedBytes)
		if c.cwnd >= c.ssthresh {
			c.state = cubicCongestionAvoidance
			c.tEpoch = time.Now()
			c.wMax = c.cwnd
		}

	case cubicCongestionAvoidance:
		// CUBIC function W(t) = C·(t-K)³ + W_max, in the BYTE domain.
		//
		// AER-075: RFC 8312 defines C, K, and W_max in SEGMENT (MSS) units.
		// This controller keeps cwnd/wMax in BYTES, so the RFC formulas must
		// be re-expressed: with W_max_seg = wMax/MSS,
		//   K       = cbrt( (wMax/MSS)·(1-β)/C )
		//   W(t)_by = MSS·C·(t-K)³ + wMax
		// The old code plugged byte-domain wMax straight into the segment
		// formulas, inflating K by ~cbrt(MSS)≈11× and deflating the growth
		// term by MSS — so after any loss cwnd effectively never regrew and
		// ratcheted to the floor on lossy paths.
		mss := float64(c.mss)
		if mss <= 0 {
			mss = float64(defaultMSS)
		}
		t := time.Since(c.tEpoch).Seconds()
		k := math.Cbrt((c.wMax / mss) * (1 - cubicBeta) / cubicC)
		wCubic := mss*cubicC*math.Pow(t-k, 3) + c.wMax

		// TCP-friendly estimate: per-ACK additive increase (RFC 8312 §4.2).
		// W_est increases by alpha_aimd·MSS·ackedBytes/cwnd per ACK. The MSS
		// factor was missing, making the increase ~1/MSS (≈1400×) too small.
		alphaAIMD := 3 * (1 - cubicBeta) / (1 + cubicBeta)
		wEst := c.cwnd + alphaAIMD*mss*(float64(ackedBytes)/c.cwnd)

		// Use the larger of CUBIC and TCP-friendly
		if wCubic > wEst {
			c.cwnd = wCubic
		} else {
			c.cwnd = wEst
		}

	case cubicFastRecovery:
		// PRR (RFC 6937) — proportional rate reduction during recovery.
		// pipeBytes == 0 means caller didn't supply the flight size,
		// fall back to legacy linear growth so we don't starve the
		// connection. recoverFS == 0 same fallback (no recovery state
		// captured).
		if pipeBytes > 0 && c.recoverFS > 0 {
			c.prrDelivered += ackedBytes
			pipe := float64(pipeBytes)
			ackedF := float64(ackedBytes)
			var sndcnt float64
			if pipe > c.ssthresh {
				// Proportional phase: drain inFlight at the same rate
				// it's being delivered, scaled by ssthresh/recoverFS.
				sndcnt = math.Ceil(float64(c.prrDelivered)*c.ssthresh/float64(c.recoverFS)) - float64(c.prrOut)
			} else {
				// Slow-start-after-recovery phase.
				gapTo := c.ssthresh - pipe
				deliveredGap := float64(c.prrDelivered-c.prrOut) + ackedF
				if deliveredGap < gapTo {
					sndcnt = deliveredGap
				} else {
					sndcnt = gapTo
				}
			}
			if sndcnt < 0 {
				sndcnt = 0
			}
			// Effective cwnd = current pipe + sndcnt budget.
			c.cwnd = pipe + sndcnt
			// Exit recovery once the inflight pipe is back to the
			// post-loss target (≥ ssthresh). The previous condition
			// (cwnd >= ssthresh && pipe < ssthresh) tripped at the
			// PRR boundary case cwnd == ssthresh + pipe slightly
			// below ssthresh, which RFC 6937 considers the SAME state
			// as "still in recovery, growing pipe". Exiting early
			// jumped to congestion avoidance before all losses had
			// been repaired (was M-CUBIC-PRR-Exit). Using pipe alone
			// matches RFC 6937 §3.2 "recovery completes when ack
			// reaches recovery_point" since pipe-recovery and ack-
			// reaching-recovery-point are coincident.
			if pipe >= c.ssthresh {
				c.state = cubicCongestionAvoidance
				c.tEpoch = time.Now()
				c.recoverFS = 0
				c.prrDelivered = 0
				c.prrOut = 0
			}
		} else {
			// Legacy fallback (no pipe supplied): grow cwnd by ackedBytes/cwnd.
			c.cwnd += float64(ackedBytes) * float64(c.mss) / c.cwnd
			if c.cwnd >= c.ssthresh {
				c.state = cubicCongestionAvoidance
				c.tEpoch = time.Now()
			}
		}
	}

	// Clamp
	if c.cwnd > float64(maxCWND) {
		c.cwnd = float64(maxCWND)
	}
	if c.cwnd < float64(minCWND) {
		c.cwnd = float64(minCWND)
	}
}

// OnSend is called by the adapter after each transmission to track
// prr_out (RFC 6937 §3.1). Outside of fast recovery this is a cheap
// no-op — only the recovery state machine consults prrOut.
//
// Returns a zero-value DeliveryRateSample to satisfy the Controller
// interface; CUBIC has no notion of delivery-rate sampling. BBR's
// implementation returns a real sample that the adapter stamps on the
// SendEntry so the matching ACK can call OnAckSampled.
func (c *CUBICController) OnSend(sentBytes int64) DeliveryRateSample {
	if sentBytes > 0 {
		c.mu.Lock()
		if c.state == cubicFastRecovery {
			c.prrOut += sentBytes
		}
		c.mu.Unlock()
	}
	return DeliveryRateSample{}
}

// ResetCWND restores cwnd to initialCWND, clears ssthresh back to a
// no-threshold state (effectively re-enters slow start), and clears
// PRR state. Called by the adapter when the probe-before-close path
// confirms the network is alive — the previous OnLoss reductions
// were over-zealous and drove cwnd to the floor. Without this, the
// session enters a deadlock where inFlight >= cwnd prevents any
// further sends and therefore any further ACKs.
//
// The adapter calls this exactly once per probe-rescue event to avoid
// repeatedly resetting cwnd if the probe path runs hot.
func (c *CUBICController) ResetCWND() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cwnd = float64(initialCWND)
	c.ssthresh = float64(maxCWND)
	c.state = cubicSlowStart
	c.tEpoch = time.Now()
	c.acked = 0
	c.wMax = 0
	c.recoverFS = 0
	c.prrDelivered = 0
	c.prrOut = 0
}

// OnCE handles ECN CE marks. Per RFC 3168 §6.1.2, treat CE the same as a
// single-RTT loss event: one CWND reduction per RTT, not per CE-marked
// packet. This is a conservative implementation: any non-zero CE byte
// count triggers exactly one OnLoss-style reduction per call. The caller
// (adapter) coalesces ACKs so OnCE only fires once per ACK frame.
func (c *CUBICController) OnCE(bytesMarked int64) {
	if bytesMarked <= 0 {
		return
	}
	c.OnLoss()
}

// OnLoss handles packet loss detection. Legacy entry point — adapters
// that have current flight-size info should prefer OnLossWithPipe so
// PRR can seed recoverFS correctly.
func (c *CUBICController) OnLoss() {
	c.OnLossWithPipe(0)
}

// OnLossWithPipe is the PRR-aware variant. pipeBytes is current
// in-flight bytes (= bytes already on the wire awaiting ACK). Seeds
// recoverFS so the proportional-rate-reduction formula has the right
// denominator in OnAckWithPipe.
//
// Idempotent across the same recovery epoch: if we're already in
// fastRecovery and a fresh OnLoss comes in (e.g. RACK declaring
// additional losses inside the same window), we DO NOT recompute
// ssthresh — that would compound the cwnd reduction beyond the RFC's
// "one reduction per RTT" rule. Per-loss accounting stays correct
// because PRR's prrDelivered/prrOut counters keep going.
func (c *CUBICController) OnLossWithPipe(pipeBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == cubicFastRecovery {
		// Already in recovery — don't re-shrink. Subsequent losses in
		// the same window are RACK / TLP marking additional packets;
		// CUBIC's recovery semantics already cover them via the
		// existing ssthresh.
		return
	}

	c.wMax = c.cwnd
	c.ssthresh = c.cwnd * cubicBeta
	if c.ssthresh < float64(minCWND) {
		c.ssthresh = float64(minCWND)
	}
	c.cwnd = c.ssthresh
	c.state = cubicFastRecovery
	c.tEpoch = time.Now()
	c.acked = 0
	// Seed PRR state for OnAckWithPipe.
	if pipeBytes > 0 {
		c.recoverFS = pipeBytes
	} else {
		// Fallback: assume pipe == cwnd (worst case for sender — most
		// conservative draining behaviour).
		c.recoverFS = int64(c.cwnd)
	}
	c.prrDelivered = 0
	c.prrOut = 0
}

// CWND returns the current congestion window in bytes.
func (c *CUBICController) CWND() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(c.cwnd)
}

// CanSend returns true if more data can be sent.
func (c *CUBICController) CanSend(inFlight int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return inFlight < int64(c.cwnd)
}

// PacingRate returns 0 — CUBIC doesn't implement pacing.
func (c *CUBICController) PacingRate() float64 {
	return 0
}

// State returns the current CUBIC state (for debugging).
func (c *CUBICController) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case cubicSlowStart:
		return "slow-start"
	case cubicCongestionAvoidance:
		return "congestion-avoidance"
	case cubicFastRecovery:
		return "fast-recovery"
	default:
		return "unknown"
	}
}
