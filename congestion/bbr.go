/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// BBRv2 congestion controller built around per-packet delivery-rate
// sampling:
//   - DeliveryRateSample stamped at send time, evaluated on ACK
//   - RoundCounter advancing once per RTT-equivalent
//   - Inflight tracking (inflightBytes / inflightHi)
//   - 4-state machine: Startup → Drain → ProbeBW → ProbeRTT
//   - 8-phase ProbeBW gain cycle: 1.25, 0.75, 1, 1, 1, 1, 1, 1
//   - 200 ms ProbeRTT every 10 s
//   - Startup exit on 3 rounds without BtlBw growth (RFC-aligned)
//
// Per-packet sample stamping happens via SendWindow.SendEntry.BBRSample:
// the adapter calls BBRController.OnSend at send time, stores the
// returned sample on the entry, and hands it back to OnAckSampled when
// the matching ACK arrives.
package congestion

import (
	"sync"
	"time"
)

// BBRv2 state machine phases.
type bbrState int

const (
	bbrStartup  bbrState = iota
	bbrDrain
	bbrProbeBW
	bbrProbeRTT
)

func (s bbrState) String() string {
	switch s {
	case bbrStartup:
		return "startup"
	case bbrDrain:
		return "drain"
	case bbrProbeBW:
		return "probe-bw"
	case bbrProbeRTT:
		return "probe-rtt"
	default:
		return "unknown"
	}
}

// BBR tunables.
const (
	bbrStartupGain  = 2.89  // 2/ln(2) — bandwidth doubles per round
	bbrDrainGain    = 0.35  // 1/2.89 — drain queue built during startup
	bbrProbeRTTCwnd = 4     // CWND in MSS units during ProbeRTT
	bbrProbeRTTDur  = 200 * time.Millisecond
	bbrProbeRTTInterval = 10 * time.Second
	bbrMinPacingRate    = 1400.0
	bbrStartupGrowthThreshold = 1.25 // BtlBw must grow ≥25% per round to stay in Startup
	bbrStartupFullCntThreshold = 3   // 3 stalled rounds → exit Startup
	bbrInflightHiHeadroom = 0.85     // CWND clamp = inflightHi * (1 - headroom)
)

// ProbeBW 8-phase gain cycle.
var bbrProbeBWGains = [8]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

// DeliveryRateSample is the per-packet metadata BBR needs to compute
// delivery rate on ACK. Stamped at send time, evaluated on ACK.
type DeliveryRateSample struct {
	SendTime       time.Time
	DeliveredBytes int64 // total bytes delivered at send time
	DeliveredTime  time.Time
	IsAppLimited   bool
}

// RoundCounter tracks BBR rounds. A round completes when the ACK for
// the first packet sent in that round arrives.
type RoundCounter struct {
	Count              uint64
	NextRoundDelivered int64
	RoundStart         bool // set true on the tick a new round begins
}

// OnAck advances the round counter when the acked packet's
// delivered-at-send is at least nextRoundDelivered.
func (r *RoundCounter) OnAck(packetDeliveredAtSend, currentDelivered int64) {
	r.RoundStart = false
	if packetDeliveredAtSend >= r.NextRoundDelivered {
		r.Count++
		r.RoundStart = true
		r.NextRoundDelivered = currentDelivered
	}
}

// BBRController implements the BBRv2 congestion controller.
type BBRController struct {
	mu sync.Mutex

	// Per-call MSS, updated by PMTU.
	mss int64

	// State machine.
	state      bbrState
	cycleIndex int
	cycleStamp time.Time

	// Bandwidth and RTT estimators.
	btlBw         float64    // bytes/sec, current bottleneck bandwidth estimate
	btlBwFilter   maxFilter  // windowed-max filter over the last N rounds
	rtProp        time.Duration
	rtPropStamp   time.Time
	probeRTTDone  time.Time
	probeRTTRound uint64

	// Round counting + delivery accounting.
	rounds        RoundCounter
	delivered     int64
	deliveredTime time.Time

	// Inflight tracking.
	inflight   int64
	inflightHi int64
	appLimited bool

	// Startup-exit detection.
	fullBwCount   int
	fullBwLastVal float64

	// Outputs.
	cwnd       int64
	pacingRate float64
}

// NewBBRController creates a BBRv2 controller.
func NewBBRController() *BBRController {
	return &BBRController{
		mss:           defaultMSS,
		state:         bbrStartup,
		rtProp:        time.Second, // initial conservative estimate
		btlBwFilter:   maxFilter{windowSize: 10},
		cwnd:          int64(initialCWND),
		pacingRate:    float64(initialCWND), // start at conservative rate
		deliveredTime: time.Now(),
	}
}

// OnSend stamps a delivery-rate sample for one in-flight packet of size n.
// The caller (SendWindow) stores the returned sample alongside the packet
// and passes it back into OnAckSampled when the packet is acked.
//
// This is the *recommended* hook for fully-modelled BBR. The simpler
// OnAck(ackedBytes, rtt) path remains for callers that don't yet
// integrate per-packet samples — those drive the controller in a
// degraded mode with rough delivery-rate estimation.
func (b *BBRController) OnSend(n int64) DeliveryRateSample {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.inflight += n
	if b.inflight > b.inflightHi && b.state != bbrStartup {
		b.inflightHi = b.inflight
	}
	// App-limited: send buffer briefly empty before this packet → cwnd
	// underutilised. Heuristic: small inflight relative to cwnd.
	b.appLimited = b.inflight < b.cwnd/2

	return DeliveryRateSample{
		SendTime:       time.Now(),
		DeliveredBytes: b.delivered,
		DeliveredTime:  b.deliveredTime,
		IsAppLimited:   b.appLimited,
	}
}

// OnAckSampled processes an ACK with the original send-time sample.
// Computes delivery rate and updates the BBR model.
func (b *BBRController) OnAckSampled(ackedBytes int64, rtt time.Duration, sample DeliveryRateSample) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.delivered += ackedBytes
	b.deliveredTime = now
	b.inflight -= ackedBytes
	if b.inflight < 0 {
		b.inflight = 0
	}

	// Delivery rate for this packet: bytes delivered between the packet's
	// send time and now, over the elapsed time on the delivery clock.
	deliveredInterval := b.delivered - sample.DeliveredBytes
	timeInterval := now.Sub(sample.DeliveredTime).Seconds()
	if timeInterval > 0 && deliveredInterval > 0 && !sample.IsAppLimited {
		dr := float64(deliveredInterval) / timeInterval
		b.btlBwFilter.update(dr)
		b.btlBw = b.btlBwFilter.max()
	}

	// MinRTT update: the lower of current rtt or the RTPropagation
	// estimate, refreshed every 10 s of staleness.
	if rtt > 0 && (rtt < b.rtProp || now.Sub(b.rtPropStamp) > bbrProbeRTTInterval) {
		b.rtProp = rtt
		b.rtPropStamp = now
	}

	// Round counter — advance when this ACK confirms delivery of a packet
	// sent in (or before) the new round.
	b.rounds.OnAck(sample.DeliveredBytes, b.delivered)

	b.runStateMachine(now)
	b.recomputeOutputs()
}

// OnAck (Controller interface) — degraded path for callers without
// per-packet sampling. Approximates delivery rate from cumulative
// bytes / elapsed since last call.
func (b *BBRController) OnAck(ackedBytes int64, rtt time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.delivered += ackedBytes
	if !b.deliveredTime.IsZero() {
		dt := now.Sub(b.deliveredTime).Seconds()
		if dt > 0 && ackedBytes > 0 {
			dr := float64(ackedBytes) / dt
			b.btlBwFilter.update(dr)
			b.btlBw = b.btlBwFilter.max()
		}
	}
	b.deliveredTime = now
	b.inflight -= ackedBytes
	if b.inflight < 0 {
		b.inflight = 0
	}
	if rtt > 0 && (rtt < b.rtProp || now.Sub(b.rtPropStamp) > bbrProbeRTTInterval) {
		b.rtProp = rtt
		b.rtPropStamp = now
	}
	b.runStateMachine(now)
	b.recomputeOutputs()
}

// OnLoss handles packet loss. BBR is loss-tolerant — single losses don't
// trigger CWND collapse like CUBIC. We trim cwnd by 15% and tighten
// inflightHi.
func (b *BBRController) OnLoss() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cwnd = int64(float64(b.cwnd) * 0.85)
	if b.cwnd < minCWND {
		b.cwnd = minCWND
	}
	if b.inflightHi > 0 {
		b.inflightHi = int64(float64(b.inflightHi) * 0.85)
	}
}

// OnCE handles ECN CE marks (#15). One RTT-bounded reduction.
func (b *BBRController) OnCE(bytesMarked int64) {
	if bytesMarked <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cwnd = int64(float64(b.cwnd) * 0.85)
	if b.cwnd < minCWND {
		b.cwnd = minCWND
	}
	// Schedule earlier ProbeRTT entry so we re-measure rtProp once the
	// queue drains.
	b.rtPropStamp = time.Now().Add(-bbrProbeRTTInterval - time.Second)
}

// CWND returns the current congestion window in bytes.
func (b *BBRController) CWND() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cwnd
}

// CanSend reports whether more data can be sent given the current cwnd.
func (b *BBRController) CanSend(inFlight int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return inFlight < b.cwnd
}

// PacingRate returns the target send rate in bytes/sec.
func (b *BBRController) PacingRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pacingRate
}

// SetMSS updates the MSS from PMTU discovery.
func (b *BBRController) SetMSS(mss int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if mss > 0 {
		b.mss = int64(mss)
		// Floor cwnd at 4×MSS so ProbeRTT remains meaningful.
		if min := int64(bbrProbeRTTCwnd) * b.mss; b.cwnd < min {
			b.cwnd = min
		}
	}
}

// State returns the current BBR state name (for debugging/observability).
func (b *BBRController) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state.String()
}

// runStateMachine advances state per the model. Caller holds b.mu.
func (b *BBRController) runStateMachine(now time.Time) {
	switch b.state {
	case bbrStartup:
		// Stay in Startup while BtlBw is growing ≥25% per round; after
		// 3 stalled rounds, transition to Drain.
		if b.rounds.RoundStart {
			if b.btlBw >= b.fullBwLastVal*bbrStartupGrowthThreshold {
				b.fullBwCount = 0
			} else {
				b.fullBwCount++
			}
			b.fullBwLastVal = b.btlBw
		}
		if b.fullBwCount >= bbrStartupFullCntThreshold {
			b.state = bbrDrain
		}

	case bbrDrain:
		// Exit Drain once inflight drops to ≈BDP.
		bdp := int64(b.btlBw * b.rtProp.Seconds())
		if b.inflight <= bdp {
			b.state = bbrProbeBW
			b.cycleIndex = 0
			b.cycleStamp = now
		}

	case bbrProbeBW:
		// Advance gain cycle every rtProp tick.
		if now.Sub(b.cycleStamp) > b.rtProp {
			b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBWGains)
			b.cycleStamp = now
		}
		// Periodic ProbeRTT entry.
		if now.Sub(b.rtPropStamp) > bbrProbeRTTInterval {
			b.state = bbrProbeRTT
			b.probeRTTDone = now.Add(bbrProbeRTTDur)
			b.probeRTTRound = b.rounds.Count
		}

	case bbrProbeRTT:
		if now.After(b.probeRTTDone) {
			b.state = bbrProbeBW
			b.cycleIndex = 0
			b.cycleStamp = now
			b.rtPropStamp = now
		}
	}
}

// recomputeOutputs derives cwnd + pacingRate from the current state.
// Caller holds b.mu.
func (b *BBRController) recomputeOutputs() {
	bdp := int64(b.btlBw * b.rtProp.Seconds())
	if bdp < minCWND {
		bdp = minCWND
	}

	switch b.state {
	case bbrStartup:
		b.pacingRate = b.btlBw * bbrStartupGain
		b.cwnd = bdp * 3 // 3× BDP to fill pipe quickly
	case bbrDrain:
		b.pacingRate = b.btlBw * bbrDrainGain
		b.cwnd = bdp * 3 // keep cwnd large while we drain at low pacing
	case bbrProbeBW:
		gain := bbrProbeBWGains[b.cycleIndex]
		b.pacingRate = b.btlBw * gain
		b.cwnd = bdp * 2
	case bbrProbeRTT:
		b.pacingRate = b.btlBw
		minProbeCwnd := int64(bbrProbeRTTCwnd) * b.mss
		b.cwnd = minProbeCwnd
	}

	// Inflight-hi clamp: never exceed observed inflight peak * headroom.
	if b.inflightHi > 0 {
		clamp := int64(float64(b.inflightHi) * bbrInflightHiHeadroom)
		if clamp < minCWND {
			clamp = minCWND
		}
		if b.cwnd > clamp*2 {
			b.cwnd = clamp * 2
		}
	}

	if b.cwnd < minCWND {
		b.cwnd = minCWND
	}
	if b.cwnd > maxCWND {
		b.cwnd = maxCWND
	}
	if b.pacingRate < bbrMinPacingRate {
		b.pacingRate = bbrMinPacingRate
	}
}

// Compile-time check
var _ Controller = (*BBRController)(nil)

// ────────────────────────────────────────────────────────────────────────
// maxFilter — windowed maximum filter for bandwidth estimation
// ────────────────────────────────────────────────────────────────────────

type maxFilter struct {
	samples    []float64
	windowSize int
}

func (f *maxFilter) update(sample float64) {
	f.samples = append(f.samples, sample)
	if len(f.samples) > f.windowSize {
		f.samples = f.samples[1:]
	}
}

func (f *maxFilter) max() float64 {
	m := 0.0
	for _, s := range f.samples {
		if s > m {
			m = s
		}
	}
	return m
}
