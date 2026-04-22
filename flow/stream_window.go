/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package flow implements credit-based flow control for Aether streams.
// Used by transports that lack native flow control (TCP, WebSocket, Noise-UDP).
// QUIC and gRPC transports skip this layer.
package flow

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

// DefaultStreamCredit is the initial flow control credit per stream (1 MB).
//
// Sized to absorb a full startup gossip burst without stalling: on a
// post-restart reconnect each peer needs a G1 full-state sync (observed
// ~80 KB per peer), and a fleet of 10 peers produces ~800 KB of outbound
// gossip in the first second. A smaller initial window (e.g. 256 KB) means
// the 4th full-sync stalls on ConsumeTimeout, every subsequent gossip
// retries piles up, and HTTP goroutines sharing the accept path starve —
// the observed "credit cascade → health-check timeout → Fly restart" loop.
//
// 1 MB covers ~12 back-to-back full syncs which is comfortably over the
// worst startup burst, and the working-set cost is bounded by
// StreamConfig.InitialCredit (consumers that know they only do small
// messages can set it lower).
const DefaultStreamCredit int64 = 1024 * 1024

// DefaultMaxStreamCredit is the initial maximum credit a stream can accumulate.
// Consumers that know they want a larger initial window set
// StreamConfig.InitialCredit explicitly.
const DefaultMaxStreamCredit int64 = 1024 * 1024

// MaxGrowableWindow is the absolute ceiling the window can be grown to at
// runtime via GrowWindow.
//
// The underlying semaphore is constructed at this capacity; effective window
// size at any point is MaxGrowableWindow - initialDeficit - dataOutstanding.
// A grow operation reduces initialDeficit (releasing capacity back to the
// semaphore); a shrink operation increases it (reclaiming from the free
// portion). 8 MB is enough for BDP on gigabit cross-region links with
// ~500 ms RTT while bounding worst-case per-peer memory.
const MaxGrowableWindow int64 = 8 * 1024 * 1024

// AutoGrantThreshold is the steady-state fraction of credit consumed before
// auto-granting. When 25% of the initial credit has accumulated since the
// last grant, a WINDOW_UPDATE fires. This is the THRESHOLD trigger — one of
// three independent triggers that fire WINDOW_UPDATE (see ReceiverConsume).
const AutoGrantThreshold = 0.25

// EagerGrantPayloadFraction: if a single received payload is at least this
// fraction of the grant threshold, fire the grant immediately instead of
// waiting for the threshold to accumulate. Handles convergence-burst and
// large-exchange patterns (e.g. full-state gossip frames) where one 70 KB
// payload can already stall the sender before the next one arrives. This is
// the EAGER trigger — purely additive to AutoGrantThreshold (doesn't change
// steady-state behaviour, only accelerates the first grant on bursty paths).
const EagerGrantPayloadFraction = 0.5

// LowWatermarkFraction: if recvCredit (outstanding grants not yet consumed
// by the sender's ACK-trip-back) drops below this fraction of currentWindow,
// fire the grant now regardless of sinceLastGrant. recvCredit tells us how
// close the sender is to stalling — waiting for a percentage-of-consumed
// threshold is the wrong signal when a single big payload can push the
// sender past the brink. This is the WATERMARK trigger — belt-and-braces
// with the EAGER trigger for paths that the EAGER rule happens to miss.
const LowWatermarkFraction = 0.25

// GrantMaxInterval caps the maximum time between grants when the receiver has
// consumed any bytes since the last grant. This is the TIMED trigger — the
// 4th independent grant trigger. It fires purely on elapsed wall-clock time
// to cover the small-payload + large-window failure mode that none of
// THRESHOLD, EAGER, or WATERMARK catch. Concrete example: a gossip stream
// with 4 MB InitialCredit processing 70 KB exchanges. THRESHOLD needs 1 MB
// (≥15 payloads), EAGER needs payload ≥ 512 KB (never fires), WATERMARK
// needs recvCredit < 1 MB (≥42 payloads consumed). With this trigger a
// grant fires after at most GrantMaxInterval regardless of payload sizing.
const GrantMaxInterval = 1 * time.Second

// MinGuaranteedWindow is the escape hatch for flow control deadlock prevention.
// Frames at or below this size (control headers, ACKs, keepalive hints) bypass
// credit accounting entirely: they never block waiting for credit and never
// consume it. This guarantees WINDOW_UPDATE and similar in-band control traffic
// can always flow, even when the stream's send window is exhausted.
const MinGuaranteedWindow int64 = 1024 // 1KB

// ConsumeTimeout is how long Consume waits for credit before returning an error.
const ConsumeTimeout = 10 * time.Second

// StreamWindow implements per-stream credit-based flow control.
//
// Sender side: Consume blocks until credit is available (up to ConsumeTimeout)
// using a golang.org/x/sync/semaphore — no busy polling, context-aware
// cancellation. Small frames (≤ MinGuaranteedWindow) bypass the semaphore
// entirely and are never charged: the escape hatch is meant for in-band
// control traffic, not a bandwidth meter.
//
// Receiver side: grants credit via WINDOW_UPDATE once the sender has consumed
// AutoGrantThreshold of the initial window. recvCredit tracks outstanding
// granted-but-not-yet-consumed credit so grants correctly reset the window
// instead of pinning at maxSize.
//
// Runtime sizing: the underlying semaphore is pre-sized to
// MaxGrowableWindow. Effective window size is
// MaxGrowableWindow - initialDeficit - dataOutstanding; GrowWindow/ShrinkWindow
// move the initialDeficit boundary to resize without rebuilding the
// semaphore. SetRTT + Stats expose observation inputs for a BDP-based
// auto-tuner (not wired by default — consumers own the sizing policy).
//
// Alternative design: a future direction is to drop the credit counter
// entirely and gate Send on write-queue depth (QUIC/HTTP/2 style offsets).
// Only worth considering if the current credit-based design proves
// inadequate.
type StreamWindow struct {
	mu sync.Mutex

	// Send-side: credit is tracked inside the semaphore. Capacity is maxSize.
	//
	//   - initialDeficit: permanently acquired at construction when
	//     initialCredit < maxSize. Enforces the initial-credit cap without
	//     ever being released.
	//   - dataOutstanding: data bytes acquired by Consume but not yet released
	//     by an incoming WINDOW_UPDATE. Grants cap at this value so we never
	//     release past the actual in-flight amount.
	//
	// Effective send credit = maxSize - initialDeficit - dataOutstanding.
	sem             *semaphore.Weighted
	maxSize         int64
	initialDeficit  int64
	dataOutstanding int64

	// currentWindow is the effective max window today (after any Grow/Shrink
	// adjustments). Tracked separately from initialSize so that autogrant
	// capping (ReceiverConsume) reflects the live target, not the
	// construction-time value. Always equals maxSize - initialDeficit.
	currentWindow int64

	// Receive-side accounting — drives auto-grant decisions.
	// recvCredit represents credit we have extended to the sender but that has
	// not yet been consumed by the data arriving at us. It decreases as we
	// receive data (we're consuming the credit we previously granted) and
	// increases when we emit a new WINDOW_UPDATE.
	initialSize int64
	recvCredit  int64
	consumed    int64
	lastGrant   int64

	// Cumulative-grant accounting — the WINDOW_UPDATE wire value is the
	// CUMULATIVE total of credit granted since stream start, not a delta.
	// This makes the grant channel idempotent across loss, duplication, and
	// reordering on unreliable transports (Noise-UDP): a lost grant is
	// implicitly retransmitted by the next one (which carries a larger
	// cumulative value), and duplicates are no-ops after the first.
	//
	//   grantsEmitted  — total bytes of credit we (receiver) have granted
	//                    so far; sent as the wire value on each WINDOW_UPDATE.
	//   grantsReceived — highest cumulative value we (sender) have seen
	//                    from peer; any incoming wire value ≤ this is stale
	//                    and dropped by ApplyUpdate.
	//   ackReleased    — cumulative bytes released through the ACK-driven
	//                    (ReleaseOnACK) path. Purely observational; the
	//                    release is still capped at dataOutstanding so
	//                    it composes safely with ApplyUpdate's release
	//                    path.
	grantsEmitted  int64
	grantsReceived int64
	ackReleased    int64

	// Auto-tuning hints — advisory data an auto-tuner reads via Stats().
	// Updated from Consume/ApplyUpdate hot paths, guarded by mu.
	peakOutstanding int64         // max dataOutstanding observed since last tune
	lastRTT         time.Duration // most recent observed RTT (from SetRTT)

	// Grant-trigger telemetry — count how often each of the four
	// WINDOW_UPDATE triggers fired. Exposed via Stats() so operators can
	// tell at a glance whether bursts (EagerGrants) or steady-state
	// consumption (ThresholdGrants) or pre-stall pressure (WatermarkGrants)
	// or wall-clock gap (TimedGrants) is driving the grant channel. Atomic
	// so Stats() is lock-free.
	thresholdGrants uint64
	eagerGrants     uint64
	watermarkGrants uint64
	timedGrants     uint64

	// lastGrantTime is the wall-clock time of the most recent grantLocked
	// call. Drives the TIMED trigger; also initialized at construction so
	// a brand-new stream can't fire TIMED on the very first payload.
	lastGrantTime time.Time
}

// NewStreamWindow creates a flow control window with the given initial credit.
//
// The underlying semaphore is sized at MaxGrowableWindow (or initialCredit
// if that's larger — for consumers that want a pre-sized large window).
// The portion above initialCredit is pre-acquired into `initialDeficit`, so
// the effective send window matches initialCredit at construction.
// GrowWindow/ShrinkWindow can later move the deficit boundary to dynamically
// resize without rebuilding the semaphore.
func NewStreamWindow(initialCredit int64) *StreamWindow {
	return NewStreamWindowWithCap(initialCredit, 0)
}

// NewStreamWindowWithCap is like NewStreamWindow but also bounds the
// semaphore capacity (growth ceiling) at `maxCredit`. Streams carrying
// small messages (gossip, control, keepalive) can use a small cap to
// bound worst-case per-stream memory — the auto-tuner will never grow
// the window above maxCredit regardless of RTT/BDP. A maxCredit of 0
// falls back to the package-level MaxGrowableWindow ceiling.
//
// maxCredit is silently raised to initialCredit if the caller passes a
// cap smaller than the starting window: the starting window always
// wins, otherwise the construction invariants (semaphore capacity ≥
// initialCredit) break.
func NewStreamWindowWithCap(initialCredit, maxCredit int64) *StreamWindow {
	if initialCredit <= 0 {
		initialCredit = DefaultStreamCredit
	}
	// Semaphore capacity is MaxGrowableWindow unless the caller asked
	// for a larger initial window OR explicitly capped growth via
	// maxCredit. maxCredit <= 0 means "use the package default"; a
	// positive value smaller than MaxGrowableWindow tightens the cap.
	capacity := MaxGrowableWindow
	if maxCredit > 0 {
		capacity = maxCredit
	}
	if initialCredit > capacity {
		capacity = initialCredit
	}

	sem := semaphore.NewWeighted(capacity)
	// Pre-acquire the gap between capacity and initialCredit so the
	// effective window equals initialCredit. This deficit is parked and
	// only released by an explicit GrowWindow call.
	var deficit int64
	if initialCredit < capacity {
		deficit = capacity - initialCredit
		// Safe: fresh semaphore has full capacity, cannot block.
		_ = sem.Acquire(context.Background(), deficit)
	}

	return &StreamWindow{
		sem:            sem,
		maxSize:        capacity,
		initialDeficit: deficit,
		initialSize:    initialCredit,
		currentWindow:  initialCredit,
		recvCredit:     initialCredit,
		lastGrantTime:  time.Now(),
	}
}

// Consume reserves n bytes of sender credit before a Send.
//
// Small frames (≤ MinGuaranteedWindow) are NOT metered — they bypass the
// semaphore entirely. See MinGuaranteedWindow's doc for rationale.
//
// Larger frames block waiting for credit, honouring ctx cancellation. After
// ConsumeTimeout with no credit the call fails; higher layers (gossip)
// surface this as "insufficient stream credit after 10s".
func (w *StreamWindow) Consume(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	if n <= MinGuaranteedWindow {
		// Escape hatch — small frames always pass, no metering. This prevents
		// deadlocks where WINDOW_UPDATE and other control traffic would be
		// stuck behind a drained data window.
		return nil
	}

	acquireCtx, cancel := context.WithTimeout(ctx, ConsumeTimeout)
	defer cancel()

	if err := w.sem.Acquire(acquireCtx, n); err != nil {
		avail := w.Available()
		dbgFlow.Printf("Consume TIMEOUT need=%d have=%d outstanding=%d maxSize=%d",
			n, avail, w.dataOutstanding, w.maxSize)
		return fmt.Errorf("aether flow: insufficient stream credit after %s (need %d, have %d): %w",
			ConsumeTimeout, n, avail, err)
	}

	w.mu.Lock()
	w.dataOutstanding += n
	if w.dataOutstanding > w.peakOutstanding {
		w.peakOutstanding = w.dataOutstanding
	}
	outstanding := w.dataOutstanding
	w.mu.Unlock()
	dbgFlow.Printf("Consume OK n=%d outstanding=%d avail=%d", n, outstanding, w.currentWindow-outstanding)
	return nil
}

// ReleaseOnACK releases sender-side credit corresponding to bytes the
// peer has acknowledged via the reliability layer's CompositeACK path
// (independent of WINDOW_UPDATE). ACKs are loss-tolerant via their own
// retransmission, so flow-control credit delivered through them is
// strictly more robust than credit delivered through bare WINDOW_UPDATE
// frames which can be dropped on lossy UDP paths.
//
// ackedBytesDelta is the byte sum of entries newly acknowledged in this
// ACK (not cumulative). Caller (the adapter's handleACK) computes this
// by summing Frame.Length over the `acked` slice returned by
// SendWindow.ProcessCompositeACK.
//
// The release is capped at dataOutstanding so ACK-path and WINDOW_UPDATE
// path together never over-release. Whichever path delivers credit first
// for a given byte wins; the other sees dataOutstanding already reduced
// and releases nothing extra.
func (w *StreamWindow) ReleaseOnACK(ackedBytesDelta int64) {
	if ackedBytesDelta <= 0 {
		return
	}
	w.mu.Lock()
	release := ackedBytesDelta
	if release > w.dataOutstanding {
		release = w.dataOutstanding
	}
	w.dataOutstanding -= release
	w.ackReleased += release
	w.mu.Unlock()
	if release > 0 {
		w.sem.Release(release)
	}
	dbgFlow.Printf("ReleaseOnACK delta=%d released=%d ackReleasedTotal=%d", ackedBytesDelta, release, w.ackReleased)
}

// ApplyUpdate processes a received WINDOW_UPDATE frame, where `credit` is
// the peer's CUMULATIVE total of credit granted since stream start (not a
// delta). The function computes the delta since the last applied grant,
// applies it, and silently drops stale / out-of-order / duplicate frames.
//
// Cumulative semantics are why this is loss-tolerant on Noise-UDP: if one
// WINDOW_UPDATE packet drops, the next one carries a still-larger
// cumulative value that re-covers what was lost. Duplicates have delta <= 0
// and return early. A re-ordered older frame also has delta <= 0 (its
// cumulative value is below what a more-recent frame already set).
//
// The delta is further capped at dataOutstanding so we never release the
// semaphore past what Consume actually acquired — preserves the invariant
// that Available() <= initialCredit at rest.
func (w *StreamWindow) ApplyUpdate(credit int64) {
	if credit <= 0 {
		return
	}
	w.mu.Lock()
	if credit <= w.grantsReceived {
		// Stale or duplicate — peer's total granted is not higher than what
		// we've already seen. Drop silently; this is the whole point of the
		// cumulative scheme.
		w.mu.Unlock()
		return
	}
	delta := credit - w.grantsReceived
	w.grantsReceived = credit
	granted := delta
	if granted > w.dataOutstanding {
		granted = w.dataOutstanding
	}
	w.dataOutstanding -= granted
	outstanding := w.dataOutstanding
	w.mu.Unlock()
	if granted > 0 {
		w.sem.Release(granted)
	}
	dbgFlow.Printf("ApplyUpdate cumulative=%d delta=%d granted=%d outstanding=%d avail=%d",
		credit, delta, granted, outstanding, w.maxSize-w.initialDeficit-outstanding)
}

// ReceiverConsume records that the receiver consumed n bytes of received data.
// Returns the credit to grant (for a WINDOW_UPDATE) if the threshold is met.
// Returns 0 if no grant is needed yet.
//
// recvCredit must be decremented by n here so the cap check in the
// grant computation reflects the currently-outstanding granted window.
// Without this decrement, recvCredit pins at maxSize when initialCredit
// == maxSize, every grant computes as 0, and the receiver never emits a
// WINDOW_UPDATE.
//
// Grant consolidation: when the threshold fires, grant enough to restore
// the sender's outstanding window to full (`currentWindow - recvCredit`)
// rather than just `sinceLastGrant`. The receiver has authoritative
// knowledge of the outstanding window, and granting the full remaining
// gap each time reduces WINDOW_UPDATE frame overhead (bursty senders get
// one big grant every ~25% consumed instead of many small ones) while
// keeping the sender's window as full as possible between grants.
// Threshold still gates WHEN we emit to avoid grant storms.
func (w *StreamWindow) ReceiverConsume(n int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.recvCredit -= n
	w.consumed += n
	sinceLastGrant := w.consumed - w.lastGrant

	threshold := int64(float64(w.initialSize) * AutoGrantThreshold)

	// Four-trigger grant emission — the sender stalls when recvCredit is
	// exhausted, so we fire under any of the following conditions. Each
	// trigger is independently sufficient; they never fight each other
	// because any one firing calls grantLocked which advances lastGrant +
	// recvCredit + lastGrantTime atomically.
	//
	//   1. THRESHOLD: sinceLastGrant >= 25% of initial. The steady-state
	//      trigger. Handles sustained low-rate traffic where the receiver
	//      accumulates a lot of small payloads between grants.
	//
	//   2. EAGER: this single payload is >= 50% of the threshold. Handles
	//      bursts where one 70 KB full-state gossip exchange can already
	//      stall a 1 MB window before the NEXT payload arrives — without
	//      this trigger the first grant has to wait for a second big
	//      payload, which can push the sender past its timeout.
	//
	//   3. WATERMARK: recvCredit (outstanding unconsumed-on-sender-side
	//      credit) has dropped below 25% of currentWindow. Direct signal
	//      of imminent sender stall — if 75%+ of what we granted is still
	//      unconsumed, the sender is at the brink regardless of what
	//      sinceLastGrant thinks. Belt-and-braces with EAGER for paths
	//      where neither THRESHOLD nor EAGER happen to fire in time.
	//
	//   4. TIMED: wall-clock gap since lastGrantTime >= GrantMaxInterval
	//      AND sinceLastGrant > 0. Covers the small-payload + large-window
	//      failure mode where the other three triggers have size floors
	//      that don't fire. With a 4 MB gossip stream and 70 KB payloads,
	//      THRESHOLD needs ~15 payloads, EAGER never fires, WATERMARK
	//      needs ~42 payloads. TIMED guarantees a grant within 1 s of any
	//      consumed byte, making the grant channel robust to any
	//      payload-size × window-size combination.
	lowWatermark := int64(float64(w.currentWindow) * LowWatermarkFraction)
	eagerPayloadFloor := int64(float64(threshold) * EagerGrantPayloadFraction)
	switch {
	case sinceLastGrant >= threshold:
		return w.grantLocked(sinceLastGrant, "threshold")
	case n >= eagerPayloadFloor && sinceLastGrant > 0:
		return w.grantLocked(sinceLastGrant, "eager")
	case w.recvCredit < lowWatermark && sinceLastGrant > 0:
		return w.grantLocked(sinceLastGrant, "watermark")
	case sinceLastGrant > 0 && time.Since(w.lastGrantTime) >= GrantMaxInterval:
		return w.grantLocked(sinceLastGrant, "timed")
	}
	return 0
}

// grantLocked emits a WINDOW_UPDATE grant and advances cumulative
// accounting. Caller must hold w.mu. Returns the cumulative wire value
// (grantsEmitted), or 0 if no grant was actually produced (guarded by the
// currentWindow - recvCredit gap which can be ≤ 0 when the window has
// been shrunk below the current outstanding).
//
// trigger is "threshold" / "eager" / "watermark" and drives the telemetry
// counters surfaced through Stats() for observability.
func (w *StreamWindow) grantLocked(sinceLastGrant int64, trigger string) int64 {
	grant := w.currentWindow - w.recvCredit
	if grant <= 0 {
		return 0
	}
	w.recvCredit += grant
	w.lastGrant = w.consumed
	w.grantsEmitted += grant
	w.lastGrantTime = time.Now()
	switch trigger {
	case "threshold":
		atomic.AddUint64(&w.thresholdGrants, 1)
	case "eager":
		atomic.AddUint64(&w.eagerGrants, 1)
	case "watermark":
		atomic.AddUint64(&w.watermarkGrants, 1)
	case "timed":
		atomic.AddUint64(&w.timedGrants, 1)
	}
	dbgFlow.Printf("ReceiverConsume grant=%d cumulative=%d trigger=%s sinceLastGrant=%d consumed=%d recvCredit=%d",
		grant, w.grantsEmitted, trigger, sinceLastGrant, w.consumed, w.recvCredit)
	return w.grantsEmitted
}

// Available returns the sender's remaining credit.
func (w *StreamWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentWindow - w.dataOutstanding
}

// CurrentGrant returns the current cumulative-emitted value so callers can
// periodically re-transmit it as a WINDOW_UPDATE. Safe on unreliable
// transports: the sender's ApplyUpdate drops any re-emit where the
// cumulative value is not greater than what's already applied, so extra
// re-emits are idempotent no-ops (correctness-wise) and harmless
// (wire-overhead-wise, at ~24-byte control frames).
//
// The refresh is important because cumulative grants normally only advance
// when the receiver's threshold is re-crossed by new incoming data. If UDP
// packet loss drops a WINDOW_UPDATE and the sender stalls, the sender's
// SIDE stops sending, the receiver therefore stops receiving, no new
// threshold is crossed, and no new grant fires — deadlock. Periodically
// re-emitting CurrentGrant breaks that deadlock: a lost grant gets
// re-transmitted, sender's ApplyUpdate computes a positive delta, the
// semaphore releases, and the sender can send again.
//
// Returns 0 if no grant has ever been emitted (receiver hasn't crossed
// the threshold at least once yet); re-emitting 0 is pointless.
func (w *StreamWindow) CurrentGrant() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.grantsEmitted
}

// CurrentWindow returns the effective send-window target (post any
// Grow/Shrink adjustments). Exported for metrics and auto-tuning observers.
func (w *StreamWindow) CurrentWindow() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentWindow
}

// GrowWindow increases the stream's effective send window by up to n bytes.
// Implementation: releases min(n, initialDeficit) of pre-acquired semaphore
// capacity back to the pool, raising the effective credit ceiling. The
// actual amount grown is returned (may be less than n if we've already
// reached the MaxGrowableWindow ceiling).
//
// Auto-tune hook: callers observing good RTT + full-utilisation can grow
// the window to raise BDP-limited throughput. Prefer small increments
// (e.g. 25% of current) to avoid oscillation.
//
// Safe to call from any goroutine.
func (w *StreamWindow) GrowWindow(n int64) int64 {
	if n <= 0 {
		return 0
	}
	w.mu.Lock()
	growable := w.initialDeficit
	if n > growable {
		n = growable
	}
	if n > 0 {
		w.initialDeficit -= n
		w.currentWindow += n
	}
	dbgFlow.Printf("GrowWindow by=%d currentWindow=%d deficit=%d", n, w.currentWindow, w.initialDeficit)
	w.mu.Unlock()
	if n > 0 {
		w.sem.Release(n)
	}
	return n
}

// ShrinkWindow decreases the stream's effective send window by up to n bytes.
// Only shrinks what isn't currently in-flight (best-effort TryAcquire on the
// semaphore). Returns the actual amount shrunk. A value < n means
// dataOutstanding was high enough that we couldn't reclaim all of n without
// blocking an active sender.
//
// Counterpart of GrowWindow. Auto-tuners call this when observed utilisation
// is low (sustained idle credit) or a congestion signal suggests backing off.
func (w *StreamWindow) ShrinkWindow(n int64) int64 {
	if n <= 0 {
		return 0
	}
	// Cap against current window so we never push the effective window
	// below zero (leaves at least 0 bytes — caller policy determines if
	// that's ever desirable; typically you want a floor well above zero).
	w.mu.Lock()
	if n > w.currentWindow {
		n = w.currentWindow
	}
	w.mu.Unlock()

	// Try to acquire the shrink amount from the semaphore (reclaiming the
	// free portion). If in-flight data plus the shrink amount would exceed
	// capacity, TryAcquire fails and we return 0.
	if !w.sem.TryAcquire(n) {
		return 0
	}
	w.mu.Lock()
	w.initialDeficit += n
	w.currentWindow -= n
	dbgFlow.Printf("ShrinkWindow by=%d currentWindow=%d deficit=%d", n, w.currentWindow, w.initialDeficit)
	w.mu.Unlock()
	return n
}

// SetRTT records an observed round-trip time for this stream. Used as input
// to BDP-based auto-tuning. Purely advisory — no side effect unless an
// auto-tuner consumes it via Stats().
func (w *StreamWindow) SetRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	w.mu.Lock()
	w.lastRTT = rtt
	w.mu.Unlock()
}

// Stats is a point-in-time snapshot of window state for metrics/auto-tuning.
type Stats struct {
	CurrentWindow   int64         // effective max window now
	Outstanding     int64         // bytes in-flight (acquired but not granted back)
	PeakOutstanding int64         // high watermark since last ResetPeak
	RecvCredit      int64         // granted credit not yet consumed on receive
	Consumed        int64         // total bytes received on this window
	LastRTT         time.Duration // most recent RTT reported via SetRTT (0 if unknown)
	GrowthHeadroom  int64         // how much more we could grow (bytes)

	// Grant-trigger breakdown — how many WINDOW_UPDATEs each trigger has
	// fired since stream start. Useful for telling apart steady-state
	// (threshold dominates), bursty (eager dominates), pre-stall
	// (watermark fires), and small-payload-large-window (timed fires)
	// traffic patterns on a per-stream basis.
	ThresholdGrants uint64
	EagerGrants     uint64
	WatermarkGrants uint64
	TimedGrants     uint64
}

// Stats returns a snapshot of the window's state. Cheap: single mu.Lock.
// Intended for an auto-tuning goroutine to sample at ~10 Hz.
func (w *StreamWindow) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		CurrentWindow:   w.currentWindow,
		Outstanding:     w.dataOutstanding,
		PeakOutstanding: w.peakOutstanding,
		RecvCredit:      w.recvCredit,
		Consumed:        w.consumed,
		LastRTT:         w.lastRTT,
		GrowthHeadroom:  w.initialDeficit,
		ThresholdGrants: atomic.LoadUint64(&w.thresholdGrants),
		EagerGrants:     atomic.LoadUint64(&w.eagerGrants),
		WatermarkGrants: atomic.LoadUint64(&w.watermarkGrants),
		TimedGrants:     atomic.LoadUint64(&w.timedGrants),
	}
}

// ResetPeak clears peakOutstanding. Called by an auto-tuner after it samples.
func (w *StreamWindow) ResetPeak() {
	w.mu.Lock()
	w.peakOutstanding = w.dataOutstanding
	w.mu.Unlock()
}

// SuggestedWindow applies a simple BDP-based heuristic and returns the
// target window size for the most recent observation window. Callers can
// then call GrowWindow/ShrinkWindow by the delta. Returns currentWindow
// unchanged if RTT is unknown or no data has been observed.
//
// Heuristic: target = max(peakOutstanding * 1.5, currentWindow * 0.5),
// bounded by [initialSize, maxSize]. The upper bound tracks the
// per-stream growth cap (set via NewStreamWindowWithCap) rather than
// the package default, so caller-imposed memory caps are honoured.
// Reads Stats atomically and does NOT mutate window state — safe for
// observational use.
func (w *StreamWindow) SuggestedWindow() int64 {
	s := w.Stats()
	if s.LastRTT == 0 || s.PeakOutstanding == 0 {
		return s.CurrentWindow
	}
	// 1.5x peak gives headroom for the next burst; floor at half of current
	// window to prevent thrashing shrinks.
	target := s.PeakOutstanding * 3 / 2
	if floor := s.CurrentWindow / 2; floor > target {
		target = floor
	}
	if target < w.initialSize {
		target = w.initialSize
	}
	if target > w.maxSize {
		target = w.maxSize
	}
	return target
}
