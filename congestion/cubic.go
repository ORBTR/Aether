/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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

// CUBICController implements the CUBIC congestion control algorithm (RFC 8312).
// CUBIC is the default congestion controller for Linux TCP and provides
// good performance on high-bandwidth, high-latency paths.
type CUBICController struct {
	mu       sync.Mutex
	cwnd     float64    // congestion window (bytes)
	ssthresh float64    // slow start threshold
	wMax     float64    // cwnd at last loss event
	tEpoch   time.Time  // start of current CUBIC epoch
	state    cubicState
	acked    int64      // bytes acked since last loss
	mss      int64      // maximum segment size (updated by PMTU discovery)
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

// OnAck processes an acknowledgment.
func (c *CUBICController) OnAck(ackedBytes int64, rtt time.Duration) {
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
		// CUBIC function: W(t) = C * (t - K)^3 + W_max
		t := time.Since(c.tEpoch).Seconds()
		k := math.Cbrt(c.wMax * (1 - cubicBeta) / cubicC)
		wCubic := cubicC*math.Pow(t-k, 3) + c.wMax

		// TCP-friendly estimate: per-ACK additive increase (RFC 8312 Section 5.8)
		// W_est increases by alpha_aimd * MSS * ackedBytes / cwnd per ACK
		alphaAIMD := 3 * (1 - cubicBeta) / (1 + cubicBeta)
		wEst := c.cwnd + alphaAIMD*(float64(ackedBytes)/c.cwnd)

		// Use the larger of CUBIC and TCP-friendly
		if wCubic > wEst {
			c.cwnd = wCubic
		} else {
			c.cwnd = wEst
		}

	case cubicFastRecovery:
		// In fast recovery, cwnd grows by ackedBytes/cwnd per ACK
		c.cwnd += float64(ackedBytes) * float64(c.mss) / c.cwnd
		if c.cwnd >= c.ssthresh {
			c.state = cubicCongestionAvoidance
			c.tEpoch = time.Now()
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

// OnLoss handles packet loss detection.
func (c *CUBICController) OnLoss() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.wMax = c.cwnd
	c.ssthresh = c.cwnd * cubicBeta
	if c.ssthresh < float64(minCWND) {
		c.ssthresh = float64(minCWND)
	}
	c.cwnd = c.ssthresh
	c.state = cubicFastRecovery
	c.tEpoch = time.Now()
	c.acked = 0
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
