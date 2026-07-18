/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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

	// bbrMinSampleInterval is the shortest delivery-clock interval over which
	// the degraded OnAck path will derive a bandwidth sample (AE-M-07). A
	// composite ACK that acks many nil-sample entries makes the adapter call
	// OnAck once per entry in a tight loop (adapter/noise_dispatch.go), and
	// b.deliveredTime is advanced to now on every call — so the 2nd..Nth calls
	// in one handler measure a sub-microsecond dt and would compute a delivery
	// rate orders of magnitude above reality (~1400 B / 1e-7 s = ~1.4e10 B/s),
	// pinning the max-filter and blasting cwnd/pacing to their clamps. Intervals
	// below this floor are too short to measure meaningfully and are skipped.
	// OnAckSampled is unaffected (it measures send->ack on the delivery clock,
	// never an inter-loop gap). 1 ms sits far above any plausible intra-loop
	// iteration gap yet below genuine inter-ACK spacing on real paths; erring
	// toward over-rejection is safe here because skipping a rough degraded
	// sample never causes a burst, whereas admitting a spurious one does.
	bbrMinSampleInterval = 1 * time.Millisecond

	// rtPropResetDefault is the rtProp seeded by ResetCWND when no
	// previous measurement survives. 100 ms is the conventional "first
	// RTT" assumption — close to LAN+1 hop, lets BBR converge on real
	// path RTT within a few rounds. Was the H-BBR-ResetCWND-DivZero fix:
	// seeding zero produced bdp=0 and an unhelpful pacing-floor stall.
	rtPropResetDefault = 100 * time.Millisecond

	// btlBwResetDefault is the bandwidth seeded by ResetCWND. 1 MB/s
	// (~8 Mbps) is conservative enough that ProbeBW will quickly grow
	// it to the real path bandwidth, and large enough that the post-
	// reset pacingRate isn't pinned to bbrMinPacingRate (1400 B/s) for
	// dozens of rounds. Same justification as rtPropResetDefault.
	btlBwResetDefault = 1_048_576.0
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

	// lastCEReduction rate-limits OnCE's CE-driven cwnd cut to one per
	// rtProp window (AE-M-06). Zero value means no CE reduction yet.
	lastCEReduction time.Time

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

	return b.sampleLocked()
}

// StampSample captures a DeliveryRateSample from the current model state
// WITHOUT mutating inflight. AER-076: the send path stamped a sample at
// frame-build time via OnSend AND incremented inflight again at actual
// transmission via the writeLoop's OnSend — double-counting every frame so
// inflight grew without bound, the Drain-exit test (inflight <= max(bdp,
// 4·mss)) never passed, and BBR pinned pacing at 0.35× and decayed to the
// floor. The build-time stamp now uses StampSample (no increment); the
// writeLoop's OnSend remains the single authoritative on-wire increment.
func (b *BBRController) StampSample() DeliveryRateSample {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sampleLocked()
}

// sampleLocked builds a DeliveryRateSample from current state. Caller holds b.mu.
func (b *BBRController) sampleLocked() DeliveryRateSample {
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
	// estimate, refreshed every 10 s of staleness. AE-M-05: capture the
	// staleness verdict BEFORE the refresh overwrites rtPropStamp, then
	// hand it to runStateMachine. Otherwise the refresh resets the stamp
	// and the ProbeBW→ProbeRTT trigger — which keys off the SAME staleness
	// — sees now.Sub(rtPropStamp)≈0 and ProbeRTT is never entered. Mirrors
	// canonical BBR, where UpdateRTprop computes rtprop_expired once and
	// CheckProbeRTT reuses it (the staleness overwrite still tracks upward
	// RTT shifts, so no capability is lost).
	rtPropExpired := now.Sub(b.rtPropStamp) > bbrProbeRTTInterval
	if rtt > 0 && (rtt < b.rtProp || rtPropExpired) {
		b.rtProp = rtt
		b.rtPropStamp = now
	}

	// Round counter — advance when this ACK confirms delivery of a packet
	// sent in (or before) the new round.
	b.rounds.OnAck(sample.DeliveredBytes, b.delivered)

	b.runStateMachine(now, rtPropExpired)
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
		// AE-M-07: only derive a bandwidth sample over an interval at least
		// bbrMinSampleInterval long. A composite ACK acking many nil-sample
		// entries drives the adapter to call OnAck once per entry in a tight
		// loop (adapter/noise_dispatch.go), and b.deliveredTime is advanced to
		// now on every call — so the 2nd..Nth calls in one handler measure a
		// sub-microsecond gap and would otherwise inject a delivery-rate sample
		// orders of magnitude above reality, pinning btlBwFilter.max and
		// blasting cwnd/pacing to their clamps. Sub-floor intervals are too
		// short to measure, so skip them rather than poison the filter; the
		// first ACK of each batch still spans a real inter-ACK interval.
		if elapsed := now.Sub(b.deliveredTime); elapsed >= bbrMinSampleInterval && ackedBytes > 0 {
			dr := float64(ackedBytes) / elapsed.Seconds()
			b.btlBwFilter.update(dr)
			b.btlBw = b.btlBwFilter.max()
		}
	}
	b.deliveredTime = now
	b.inflight -= ackedBytes
	if b.inflight < 0 {
		b.inflight = 0
	}
	// AER-085: advance the round counter in the degraded path too. Without a
	// per-packet delivered-at-send sample we approximate a round as one BDP of
	// new delivery — advance once b.delivered passes NextRoundDelivered, then
	// re-seed it a flight ahead. Otherwise RoundStart never fires and the
	// Startup exit (which requires 3 stalled rounds) can never trigger, pinning
	// a sample-less session at 2.89× pacing / 3×BDP forever.
	if b.delivered >= b.rounds.NextRoundDelivered {
		b.rounds.Count++
		b.rounds.RoundStart = true
		incr := b.inflight
		if incr < b.mss {
			incr = b.mss
		}
		b.rounds.NextRoundDelivered = b.delivered + incr
	} else {
		b.rounds.RoundStart = false
	}
	// AE-M-05: capture staleness before the refresh resets rtPropStamp; see OnAckSampled.
	rtPropExpired := now.Sub(b.rtPropStamp) > bbrProbeRTTInterval
	if rtt > 0 && (rtt < b.rtProp || rtPropExpired) {
		b.rtProp = rtt
		b.rtPropStamp = now
	}
	b.runStateMachine(now, rtPropExpired)
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

// OnLossWithPipe — BBR doesn't use PRR (its bandwidth-delay model
// doesn't need a proportional drainer), so pipeBytes is ignored and
// the call is forwarded to OnLoss. Adapter callers pass pipeBytes
// unconditionally so the same call site works for both controllers.
func (b *BBRController) OnLossWithPipe(pipeBytes int64) {
	b.OnLoss()
}

// OnAckWithPipe — BBR uses its own delivery-rate sample machinery and
// doesn't gain anything from PRR, so this forwards to OnAck. The
// recommended path for BBR remains OnAckSampled (with a stamped
// DeliveryRateSample); OnAckWithPipe exists purely to satisfy the
// Controller interface for adapters that don't carry samples.
func (b *BBRController) OnAckWithPipe(ackedBytes int64, rtt time.Duration, pipeBytes int64) {
	b.OnAck(ackedBytes, rtt)
}

// ResetCWND restores BBR to a fresh-startup state — cwnd back to the
// initial value, model state cleared (rtProp/btlBw/inflightHi). Called
// by the adapter when probe-before-close confirms the path is alive
// after a stretch of cumulative loss-driven cwnd shrinkage.
//
// Functionally equivalent to constructing a fresh BBRController, but
// preserves the controller pointer so atomic.Pointer holders
// (NoiseSession.cong) don't need a swap.
//
// rtProp and btlBw are seeded with sensible defaults (rtPropResetDefault,
// btlBwResetDefault) rather than zeroes — was the H-BBR-ResetCWND-DivZero
// finding. With both at zero, recomputeOutputs produces bdp=0 (clamped
// to minCWND) and pacingRate=0 (clamped to bbrMinPacingRate which is
// 1400 B/s — far below useful), so post-reset the sender spends many
// rounds at near-floor pacing before BBR's filters re-converge. Seeding
// at modest defaults gives the controller a non-degenerate starting
// state while preserving fast convergence to true path properties.
func (b *BBRController) ResetCWND() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cwnd = int64(initialCWND)
	b.inflight = 0
	b.inflightHi = 0
	b.rtProp = rtPropResetDefault
	b.rtPropStamp = time.Time{}
	b.btlBw = btlBwResetDefault
	b.appLimited = false
	b.state = bbrStartup
	b.fullBwCount = 0
	b.fullBwLastVal = 0
	b.recomputeOutputs()
}

// OnCE handles ECN CE marks (#15). One RTT-bounded reduction.
func (b *BBRController) OnCE(bytesMarked int64) {
	if bytesMarked <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// AE-M-06: rate-limit CE-driven reductions to one per rtProp window.
	// The adapter calls OnCE once per CE-bearing composite ACK, and a
	// peer (or a compliant receiver reporting CE on multiple ACKs per
	// RTT) can drive back-to-back calls while data is in flight; without
	// this gate each one applies another 0.85× cut plus a forced ProbeRTT
	// re-entry, collapsing throughput. The doc comment above already
	// promises "One RTT-bounded reduction" but nothing enforced it. This
	// mirrors CUBIC's recovery-epoch idempotence (OnLossWithPipe
	// early-returns while already in fastRecovery), coalescing repeated CE
	// marks within one RTT into a single reduction. The reaction magnitude
	// is unchanged — the full 0.85× cut and ProbeRTT re-entry still fire on
	// the first CE of each RTT; only the per-RTT frequency is bounded.
	now := time.Now()
	if !b.lastCEReduction.IsZero() && now.Sub(b.lastCEReduction) < b.rtProp {
		return
	}
	b.lastCEReduction = now
	b.cwnd = int64(float64(b.cwnd) * 0.85)
	if b.cwnd < minCWND {
		b.cwnd = minCWND
	}
	// Schedule earlier ProbeRTT entry so we re-measure rtProp once the
	// queue drains.
	b.rtPropStamp = now.Add(-bbrProbeRTTInterval - time.Second)
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
func (b *BBRController) runStateMachine(now time.Time, rtPropExpired bool) {
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
		// Exit Drain once inflight drops to ≈BDP. If btlBw is zero —
		// because Startup exited without ever updating the filter
		// (entirely-app-limited stream) — bdp would be 0 and Drain
		// could only exit when inflight reaches 0. With any data in
		// flight, the controller would be permanently stuck (was
		// H-BBR-Drain-Deadlock). Apply a floor on the exit threshold
		// so Drain can always reach ProbeBW within bounded time even
		// when the bandwidth filter has nothing to anchor on.
		bdp := int64(b.btlBw * b.rtProp.Seconds())
		exitThreshold := bdp
		if exitThreshold < int64(b.mss)*4 {
			exitThreshold = int64(b.mss) * 4
		}
		if b.inflight <= exitThreshold {
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
		// Periodic ProbeRTT entry. AE-M-05: key off the pre-refresh
		// staleness verdict rtPropExpired, NOT now.Sub(rtPropStamp) — the
		// ack-path refresh already reset rtPropStamp to now, so re-reading
		// it here is always ≈0 and ProbeRTT would never be entered.
		if rtPropExpired {
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
	if len(f.samples) >= f.windowSize {
		// Shift left and overwrite the tail so the backing array stays
		// at windowSize entries — was L-BBR-MaxFilter-Backing: the
		// previous `samples[1:]` slid the slice header but kept the
		// original backing array growing unboundedly under repeated
		// append+reslice. With copy-then-overwrite the backing array
		// is bounded by windowSize forever.
		copy(f.samples, f.samples[1:])
		f.samples[len(f.samples)-1] = sample
		return
	}
	f.samples = append(f.samples, sample)
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
