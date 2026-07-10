/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package congestion

import (
	"sync"
	"time"
)

// RACK (Recent ACKnowledgement) loss detection per RFC 8985.
//
// Replaces RTO-driven OnLoss as the primary loss signal. The RTO path
// remains as a final safety net for tail-loss scenarios that RACK cannot
// see (no further ACKs ever arriving), but in steady-state RACK gives
// the controller far more accurate per-packet loss decisions:
//
//   - One isolated packet drop no longer triggers a CWND reduction every
//     time it RTO-retransmits. A single OnLoss fires when RACK identifies
//     it as lost; subsequent retransmits do not re-trigger congestion
//     control.
//   - Reordering is tolerated up to a dynamic reorder window (rackReoWnd),
//     so paths that reorder packets without true loss don't waste CWND.
//   - Loss decisions are tied to delivery time, not retransmit count, so
//     "stuck base" head-of-line scenarios that previously cumulated
//     OnLoss until CWND collapsed are diagnosed once and only once.
//
// Per-stream state. The reliability layer owns one *RACK per noiseStream
// and feeds it (xmit_time, ackTime) per delivered packet, then periodically
// calls DetectLost() to enumerate seqNos to retransmit.
type RACK struct {
	mu sync.Mutex

	// fack is the XmitTime of the most recently delivered packet seen by
	// this RACK. Per RFC 8985 §6.1: "the transmission time of the most
	// recently delivered packet, called RACK.fack". A packet whose
	// XmitTime is older than fack - reoWnd is presumed lost.
	fack time.Time

	// fackSeq is the seq of the packet that set fack. Used purely for
	// diagnostic / log correlation; loss decisions don't depend on it.
	fackSeq uint32

	// lastDeliveredAt is the wall-clock time we observed the delivery
	// that updated fack. Used as the time origin for the reoWnd timer:
	// a frame is loss-eligible only after lastDeliveredAt + reoWnd has
	// passed (RFC 8985 §6.2 condition (3)).
	lastDeliveredAt time.Time

	// reoWnd is the current reorder tolerance window. Starts conservative
	// (min(SRTT/4, 1ms)) and grows up to a cap when reordering is
	// detected. Per §7.2 of RFC 8985: each time RACK marks a lost packet
	// that subsequently arrives, reoWnd is bumped so the next decision
	// gives the network more slack.
	reoWnd time.Duration

	// reoWndPersist counts consecutive RACK loss events without observed
	// reordering. After a few clean detections we shrink reoWnd back
	// toward the floor — long-term we don't want a single-time reorder
	// to permanently inflate the loss-detection delay.
	reoWndPersist int

	// dsack records whether we've observed a DSACK (acknowledgement that
	// a previously-marked-lost packet actually arrived). DSACKs are the
	// strongest reordering signal RACK has and are the primary trigger
	// for reoWnd inflation.
	dsackSeen bool

	// minRTT tracks the smallest observed RTT for this stream. Used as
	// a floor when computing reoWnd to avoid pathological tiny windows
	// on links with sub-millisecond RTT (loopback / same-host).
	minRTT time.Duration

	// markedLost is the set of seqNos RACK has already declared lost.
	// Prevents the loss enumerator from triggering OnLoss twice for the
	// same packet across consecutive ticks. Cleared on Ack() so the same
	// seq can be re-marked if an unlikely re-issue happens.
	markedLost map[uint32]bool
}

const (
	// rackReoWndFloor is the minimum reorder window. Floored at 1ms so
	// sub-millisecond same-host RTT doesn't produce a window of 0
	// (which would identify every packet as lost the instant it's sent).
	rackReoWndFloor = 1 * time.Millisecond

	// rackReoWndCap is the maximum reorder window — grows on persistent
	// reordering, capped so we don't delay loss detection unboundedly on
	// pathological networks.
	rackReoWndCap = 200 * time.Millisecond

	// rackReoWndStep is how much reoWnd inflates per DSACK (or per
	// observed reorder event). Doubling overshoots; +SRTT/8 gives a
	// gentle adaptive growth that converges within a handful of events.
	rackReoWndStepDivisor = 8

	// rackReoShrinkAfter — number of clean RACK decisions (no DSACKs
	// observed) before reoWnd shrinks back toward the floor. Linear
	// shrinkage keeps the transition smooth.
	rackReoShrinkAfter = 16
)

// NewRACK creates a per-stream RACK detector with the given initial RTT.
// Pass 0 if RTT is unknown — reoWnd will use the floor until the first
// RTT is reported via UpdateRTT.
func NewRACK(initialRTT time.Duration) *RACK {
	r := &RACK{
		minRTT:     initialRTT,
		markedLost: make(map[uint32]bool),
	}
	r.reoWnd = r.computeReoWnd()
	return r
}

// computeReoWnd returns max(floor, min(SRTT/4, cap)). Caller must hold mu.
func (r *RACK) computeReoWnd() time.Duration {
	if r.minRTT <= 0 {
		return rackReoWndFloor
	}
	w := r.minRTT / 4
	if w < rackReoWndFloor {
		return rackReoWndFloor
	}
	if w > rackReoWndCap {
		return rackReoWndCap
	}
	return w
}

// UpdateRTT refreshes the per-stream minRTT estimate. Called from the
// adapter's RTT estimator on each ACK. RACK uses minRTT (not SRTT) to
// compute reoWnd because the floor matters more than the average for
// reorder detection: SRTT inflates after a loss event, so using SRTT
// would inflate reoWnd exactly when we want it tight.
func (r *RACK) UpdateRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.minRTT == 0 || rtt < r.minRTT {
		r.minRTT = rtt
		r.reoWnd = r.computeReoWnd()
	}
}

// Ack records that a packet has been delivered. seq + xmitTime come from
// the SendEntry; ackTime is "now" at the moment the ACK was processed.
// Per RFC 8985 §6.1, fack only advances on truly-progressing deliveries —
// retransmits whose original arrived after their newer copy don't reduce
// fack.
func (r *RACK) Ack(seq uint32, xmitTime, ackTime time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// AE-L-05: a seq RACK previously declared lost that is now being
	// acknowledged is DSACK evidence — the packet was reordered past reoWnd,
	// not truly lost. Inflate the reorder window (RFC 8985 §7.2) BEFORE the
	// delete below clears the markedLost entry, so genuinely-reordering paths
	// widen their tolerance instead of re-declaring the same in-order-late
	// packets lost every tick. This is the production wiring for OnDSACK:
	// markedLost membership is the DSACK signal the adapter's ACK path already
	// carries in via rack.Ack (noise_dispatch.go), so no adapter change or new
	// RACK API is needed. inflateReoWndLocked sets dsackSeen, which makes the
	// clean-shrink block below skip this Ack — matching the intended
	// OnDSACK-then-Ack sequence.
	if r.markedLost[seq] {
		r.inflateReoWndLocked()
	}
	delete(r.markedLost, seq)
	if xmitTime.After(r.fack) {
		r.fack = xmitTime
		r.fackSeq = seq
		r.lastDeliveredAt = ackTime
	}
	// Clean shrinking: each clean Ack without a DSACK in between
	// drains the persist counter so reoWnd can creep back to the floor.
	if !r.dsackSeen {
		r.reoWndPersist++
		if r.reoWndPersist >= rackReoShrinkAfter {
			r.reoWndPersist = 0
			target := r.computeReoWnd()
			if r.reoWnd > target {
				// Linear shrink — half the gap each step.
				r.reoWnd = r.reoWnd - (r.reoWnd-target)/2
				if r.reoWnd < target {
					r.reoWnd = target
				}
			}
		}
	}
	r.dsackSeen = false
}

// OnDSACK is called when the adapter sees evidence (via SACK or
// duplicate-data delivery on a re-sent seq) that a previously-marked-lost
// packet actually arrived. This is the strongest reorder signal RACK has
// and is the primary trigger for reoWnd inflation.
func (r *RACK) OnDSACK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflateReoWndLocked()
}

// inflateReoWndLocked widens reoWnd by one adaptive step in response to a
// DSACK (a previously-marked-lost packet proven to have arrived). Caller
// must hold mu. AE-L-05: shared by the exported OnDSACK and the in-Ack DSACK
// detection so both reorder-evidence paths grow the window identically per
// RFC 8985 §7.2, still capped at rackReoWndCap.
func (r *RACK) inflateReoWndLocked() {
	r.dsackSeen = true
	r.reoWndPersist = 0
	step := r.minRTT / rackReoWndStepDivisor
	if step < time.Millisecond {
		step = time.Millisecond
	}
	r.reoWnd += step
	if r.reoWnd > rackReoWndCap {
		r.reoWnd = rackReoWndCap
	}
}

// LossCandidate is a seq + the wall-clock time at which the adapter must
// re-check it. now < ReexamineAt → no decision yet (the entry hasn't
// aged past reoWnd); now >= ReexamineAt → declare lost and retransmit.
//
// Returning candidates rather than booleans lets the adapter set a single
// timer at min(ReexamineAt) instead of polling every tick — the
// implementation chooses but the API supports both styles.
type LossCandidate struct {
	Seq          uint32
	ReexamineAt  time.Time
	IsLossNow    bool
}

// DetectLost iterates the supplied snapshot of in-flight (seq, xmitTime)
// entries and returns the seqs that RACK declares lost as of `now`, plus
// the earliest ReexamineAt across not-yet-decided entries (caller can use
// this to schedule a wakeup so detection latency is bounded by the timer
// rather than the reliability-tick cadence).
//
// Uses RFC 8985 §6.2 condition: a packet is lost if all of:
//   1) It was sent before the most recently delivered packet (xmitTime < fack)
//   2) Its XmitTime is at least reoWnd in the past relative to fack OR
//      lastDeliveredAt + reoWnd has elapsed since delivery.
//
// We collapse (2) to: xmitTime <= fack - reoWnd  AND  now - lastDeliveredAt >= 0
// since the second clause is satisfied as soon as fack advances, which is
// what triggered this DetectLost call.
//
// Returns (lost []uint32, nextWakeup time.Time). nextWakeup is zero if
// nothing is currently in flight that's not yet decided.
func (r *RACK) DetectLost(snap []SendEntrySnapshot, now time.Time) (lost []uint32, nextWakeup time.Time) {
	r.mu.Lock()
	fack := r.fack
	reoWnd := r.reoWnd
	markedLost := make(map[uint32]bool, len(r.markedLost))
	for k, v := range r.markedLost {
		markedLost[k] = v
	}
	r.mu.Unlock()

	if fack.IsZero() {
		// No deliveries yet — RACK can't decide. Caller falls back to
		// RTO. Return zero wakeup so the caller doesn't schedule a
		// pointless RACK timer.
		return nil, time.Time{}
	}

	cutoff := fack.Add(-reoWnd)
	for _, e := range snap {
		if markedLost[e.Seq] {
			// Already declared lost on a previous tick. Adapter is
			// responsible for retransmit; we don't double-count.
			continue
		}
		if e.XmitTime.Before(fack) {
			if !e.XmitTime.After(cutoff) {
				// xmitTime <= fack - reoWnd → presumed lost (RFC 8985 §6.2).
				lost = append(lost, e.Seq)
			} else {
				// Within reorder window. The cutoff is fixed at
				// fack-reoWnd (it can only change when fack advances
				// via a new ACK), so time alone won't transition this
				// entry to loss-eligible. We schedule a wakeup at the
				// hypothetical "if cutoff were time-decreasing"
				// crossing point — the entry's XmitTime + reoWnd —
				// purely so the caller's adaptive scheduler has a
				// hint to re-poll roughly when something might change.
				// Real loss transitions happen on ACK arrival.
				wake := e.XmitTime.Add(reoWnd)
				if wake.After(now) && (nextWakeup.IsZero() || wake.Before(nextWakeup)) {
					nextWakeup = wake
				}
			}
		}
		// e.XmitTime >= fack → newer than the latest delivery, not loss-eligible.
	}

	if len(lost) > 0 {
		r.mu.Lock()
		for _, seq := range lost {
			r.markedLost[seq] = true
		}
		r.mu.Unlock()
	}
	return lost, nextWakeup
}

// SendEntrySnapshot is a minimal read-only view of an in-flight frame's
// metadata. Defined here (not imported from reliability) so the
// congestion package has no upward dependency on reliability — callers
// translate reliability.SnapshotEntry into this shape.
type SendEntrySnapshot struct {
	Seq      uint32
	XmitTime time.Time
}

// State exposes the current RACK state for diagnostic logging
// (FLOW-DIAG dumps). Not used in the loss-decision path.
type State struct {
	Fack            time.Time
	FackSeq         uint32
	LastDeliveredAt time.Time
	ReoWnd          time.Duration
	MinRTT          time.Duration
	MarkedLost      int
}

// Snapshot returns the current RACK state. Cheap (single mu.Lock).
func (r *RACK) Snapshot() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return State{
		Fack:            r.fack,
		FackSeq:         r.fackSeq,
		LastDeliveredAt: r.lastDeliveredAt,
		ReoWnd:          r.reoWnd,
		MinRTT:          r.minRTT,
		MarkedLost:      len(r.markedLost),
	}
}
