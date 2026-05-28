/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package congestion

import (
	"sync"
	"time"
)

// TLP (Tail Loss Probe) per RFC 8985 §7.
//
// Solves the deadlock case where:
//   - Data is in flight
//   - cwnd has been collapsed to its floor by accumulated OnLoss events
//   - inFlight >= cwnd, so the sender can't send any new packet under
//     congestion control
//   - No new ACK arrives because the receiver has nothing new to ACK
//   - Without further ACKs, RACK has nothing to advance fack with, so
//     it never declares the stuck packet lost
//   - Without RACK declarations, RTO is the only path forward — but
//     each RTO retransmit again triggers OnLoss, perpetuating the
//     collapsed cwnd
//
// TLP breaks the deadlock by sending exactly one packet OUTSIDE the cwnd
// when no ACK has arrived for PTO (Probe Timeout) seconds. The TLP probe
// elicits an ACK (or a SACK that reveals the loss), giving RACK the data
// it needs to make a decision and break the deadlock.
//
// TLP packets are NOT counted against cwnd; they're a transport-layer
// admission to the network outside congestion control. This is the same
// rule TCP and QUIC use (RFC 8985 §7.5, RFC 9002 §6.2.4).
//
// Per-stream state. The reliability layer owns one *TLP per noiseStream
// and arms it when there's data in flight.
type TLP struct {
	mu sync.Mutex

	// scheduledAt is the wall-clock time the next TLP probe should fire.
	// Zero = TLP is not currently armed (no data in flight, or we just
	// fired and are waiting for the response).
	scheduledAt time.Time

	// pendingProbeSeq is the SeqNo of the in-flight TLP probe (zero if
	// none in flight). Set by MarkProbeSent when the adapter actually
	// transmits the probe; cleared by MarkProbeAcked when the probe
	// returns. Used to suppress double-probes on the next tick if the
	// previous probe is still outstanding.
	pendingProbeSeq uint32
	probePending    bool

	// consecutiveProbes counts back-to-back probes without an
	// intervening ACK. Caps at maxConsecutiveProbes — beyond that we
	// declare the path dead and let the session-level stall detector
	// take over (probe-before-close → final close). Per RFC 8985 §7.5
	// this is bounded to avoid unbounded probe traffic on a fully
	// black-holed path.
	consecutiveProbes int

	// minRTT seeds PTO computation. SRTT is preferred when available
	// (PTO = 2*SRTT + max_ack_delay), but PTO must not collapse below
	// a floor on sub-millisecond paths.
	srtt time.Duration

	// maxAckDelay is the receiver's advertised maximum ACK delay. We
	// don't currently parse this from peer ACK frames so it defaults
	// to a conservative 25ms (matches QUIC default per RFC 9000).
	maxAckDelay time.Duration
}

const (
	// tlpPTOFloor — the minimum PTO. Without this, sub-ms RTT paths
	// would fire TLPs every microsecond.
	tlpPTOFloor = 10 * time.Millisecond

	// tlpPTOCeiling — upper bound on PTO. A path with multi-second
	// RTT shouldn't disable TLP entirely; capping at 1s keeps the
	// probe responsive without being aggressive.
	tlpPTOCeiling = 1 * time.Second

	// tlpPTOMultiplier — RFC 8985 §7.2 specifies 2*SRTT + max_ack_delay.
	tlpPTOMultiplier = 2

	// tlpDefaultMaxAckDelay — receiver's advertised max ACK delay.
	// Matches QUIC default. Real value would come from the handshake.
	tlpDefaultMaxAckDelay = 25 * time.Millisecond

	// maxConsecutiveProbes — give up after this many back-to-back
	// probes with no ACK. The session-level stall detector and
	// probe-before-close take over from here.
	maxConsecutiveProbes = 3
)

// NewTLP constructs a TLP scheduler with the given initial SRTT. Pass 0
// for unknown — PTO will use the floor until the first SRTT update.
func NewTLP(initialSRTT time.Duration) *TLP {
	return &TLP{
		srtt:        initialSRTT,
		maxAckDelay: tlpDefaultMaxAckDelay,
	}
}

// computePTO returns 2*SRTT + max_ack_delay, bounded by [floor, ceiling].
// Caller must hold mu.
func (t *TLP) computePTO() time.Duration {
	pto := tlpPTOMultiplier*t.srtt + t.maxAckDelay
	if pto < tlpPTOFloor {
		return tlpPTOFloor
	}
	if pto > tlpPTOCeiling {
		return tlpPTOCeiling
	}
	return pto
}

// UpdateSRTT refreshes the SRTT estimate and re-arms the timer if needed.
func (t *TLP) UpdateSRTT(srtt time.Duration) {
	if srtt <= 0 {
		return
	}
	t.mu.Lock()
	t.srtt = srtt
	t.mu.Unlock()
}

// Arm schedules a TLP for `inFlightSince + PTO`. Called by the adapter
// each time a new data frame is sent (or the in-flight set otherwise
// changes such that the "tail" packet is younger). Idempotent — calling
// Arm with a later time replaces an earlier scheduled time.
//
// inFlightSince should be the XmitTime of the most recently transmitted
// in-flight packet. If there's no in-flight data, the caller passes
// time.Time{} which disarms the timer.
func (t *TLP) Arm(inFlightSince time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if inFlightSince.IsZero() {
		t.scheduledAt = time.Time{}
		return
	}
	t.scheduledAt = inFlightSince.Add(t.computePTO())
}

// Disarm clears any pending TLP. Called when in-flight transitions to
// empty (everything ACKed) or when the session is closing.
func (t *TLP) Disarm() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scheduledAt = time.Time{}
	t.probePending = false
	t.pendingProbeSeq = 0
	t.consecutiveProbes = 0
}

// ShouldProbe reports whether the adapter should send a TLP probe right
// now. Returns true when:
//   - The TLP is armed (scheduledAt is set, i.e. there's data in flight),
//   - The scheduled PTO has elapsed (now >= scheduledAt),
//   - We haven't exhausted maxConsecutiveProbes (the session-level
//     stall detector — noise_reliability.go [STALL-DETECT] — handles
//     the fully black-holed case from there).
//
// NOTE: This deliberately does NOT gate on probePending. RFC 8985 §7.5
// and RFC 9002 §6.2.4 allow back-to-back probes (up to N) without an
// intervening ACK so that a single dropped probe doesn't permanently
// wedge the connection. The earlier "probePending blocks ShouldProbe"
// behaviour fired exactly one probe per stream and then, if that probe
// was lost on the wire (the very case we built TLP to handle), the
// stream stayed wedged forever because no subsequent probe could fire.
// consecutiveProbes — incremented on every MarkProbeSent and capped at
// maxConsecutiveProbes — provides the correct giving-up signal: after
// N consecutive un-ACKed probes the session stall path takes over.
//
// On true, the adapter selects which seq to probe (typically the
// largest in-flight seq, per RFC 8985 §7.4) and calls MarkProbeSent.
func (t *TLP) ShouldProbe(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.scheduledAt.IsZero() {
		return false
	}
	if t.consecutiveProbes >= maxConsecutiveProbes {
		return false
	}
	return !now.Before(t.scheduledAt)
}

// NextWakeup returns the wall-clock time at which ShouldProbe will next
// transition to true. Zero if disarmed or if we've exhausted
// maxConsecutiveProbes (session-level stall detector takes over).
// Like ShouldProbe, this does NOT gate on probePending — a re-arm with
// a new XmitTime is what schedules the next probe, and consecutiveProbes
// is the give-up signal.
func (t *TLP) NextWakeup() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.scheduledAt.IsZero() {
		return time.Time{}
	}
	if t.consecutiveProbes >= maxConsecutiveProbes {
		return time.Time{}
	}
	return t.scheduledAt
}

// MarkProbeSent records that a probe was just sent for seq. Stores the
// probe seq so MarkProbeAcked can recognise the returning ACK, and
// increments the consecutive-probe counter. After maxConsecutiveProbes
// without an intervening ACK, ShouldProbe stops firing and the session-
// level stall detector takes over (see noise_reliability.go
// [STALL-DETECT]).
//
// Does NOT block subsequent probes by itself — that's deliberate (see
// ShouldProbe's doc comment for the RFC rationale). The next probe is
// gated by scheduledAt (re-Arm'd by the adapter from the freshest
// in-flight XmitTime) and consecutiveProbes.
func (t *TLP) MarkProbeSent(seq uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.probePending = true
	t.pendingProbeSeq = seq
	t.consecutiveProbes++
}

// MarkProbeAcked records that an ACK arrived for the in-flight probe.
// Resets consecutiveProbes (we got a response, network is responsive)
// and clears the pending-probe state.
func (t *TLP) MarkProbeAcked() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.probePending = false
	t.pendingProbeSeq = 0
	t.consecutiveProbes = 0
}

// AnyAckReceived is called by the adapter for every ACK (not just probe
// ACKs). Resets the consecutiveProbes counter — if real data is being
// ACKed normally we don't want a stale probe count to suppress future
// TLPs.
func (t *TLP) AnyAckReceived() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.consecutiveProbes = 0
}

// PendingProbeSeq returns (seq, true) if a probe is currently in flight,
// (0, false) otherwise. Used by the adapter to recognise the probe ACK.
func (t *TLP) PendingProbeSeq() (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pendingProbeSeq, t.probePending
}

// State exposes the current TLP state for diagnostic logging.
type TLPState struct {
	ScheduledAt       time.Time
	ProbePending      bool
	PendingProbeSeq   uint32
	ConsecutiveProbes int
	PTO               time.Duration
}

// Snapshot returns the current TLP state.
func (t *TLP) Snapshot() TLPState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TLPState{
		ScheduledAt:       t.scheduledAt,
		ProbePending:      t.probePending,
		PendingProbeSeq:   t.pendingProbeSeq,
		ConsecutiveProbes: t.consecutiveProbes,
		PTO:               t.computePTO(),
	}
}
