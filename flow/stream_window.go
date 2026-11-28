/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */

// Package flow implements credit-based flow control for Aether streams.
// Used by transports that lack native flow control (TCP, WebSocket, Noise-UDP).
// QUIC and gRPC transports skip this layer.
package flow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether/metrics"
	"golang.org/x/sync/semaphore"
)

// DefaultStreamCredit is the initial flow control credit per stream (1 MB), the
// bounds profile's stream credit (CurrentBounds).
//
// Sized to absorb a full startup gossip burst without stalling: when a
// node's peers all reconnect to it at once, each needs a full-state gossip
// sync (about 80 KB per peer), and a fleet of 10 peers produces ~800 KB of
// outbound gossip in the first second. A smaller initial window (e.g.
// 256 KB) stalls the 4th full sync on ConsumeTimeout, every later gossip
// send queues behind it, and the goroutines that share the accept path with
// those sends starve, so the node's own health check times out and its host
// restarts it, which starts the burst again.
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

// MinGuaranteedWindow is the least credit a stream's window ever holds:
// NewStreamWindowWithCap raises a smaller initial credit to it and ShrinkWindow
// stops at it, so a message of this size can always be admitted once the
// receiver has consumed what is outstanding. It frees no frame from credit:
// Consume charges every byte, because the receive queue is bounded only by
// what credit admits. WINDOW_UPDATE, ACK, PING and every other control frame
// reach the write path through writeFrame and never call Consume, so an
// exhausted data window holds none of them back.
const MinGuaranteedWindow int64 = 1024 // 1KB

// ErrCreditExhausted is the typed backpressure a sender sees when its stream
// or connection window stayed empty until ConsumeTimeout or its context ended:
// the peer's consumer has not taken what is outstanding. Every Consume failure
// wraps it, so errors.Is tells backpressure from a failed write; the bytes are
// not sent and nothing has been lost. A byte-stream session holds no credit and
// answers with the same error when the queue between its Send and the conn stays
// full the same way (tcpStream.awaitSendRoom), so a caller reads one backpressure on
// every profile.
var ErrCreditExhausted = errors.New("aether flow: credit exhausted")

// ConsumeTimeout is how long Consume waits for credit before returning an error.
const ConsumeTimeout = 10 * time.Second

// ErrWaitEnded is what a credit wait answers when the done channel its caller passed
// to ConsumeUntil closes before the credit comes: what owns the window has ended (the
// adapter passes its session's close signal), so no grant will come, and the caller
// answers that end instead. It does not wrap ErrCreditExhausted, since no credit was
// found short; nothing has been charged.
var ErrWaitEnded = errors.New("aether flow: the credit wait ended")

// endWaitOn cancels a credit wait's context when done closes, and returns the stop
// that ends the watch and reports whether done had closed. A nil done never closes,
// and the watch starts no goroutine. StreamWindow.ConsumeUntil and
// ConnWindow.ConsumeUntil call it on their blocking path only, so a wait that finds
// credit at once costs nothing.
func endWaitOn(done <-chan struct{}, cancel context.CancelFunc) (stop func() bool) {
	if done == nil {
		return func() bool { return false }
	}
	quit := make(chan struct{})
	go func() {
		select {
		case <-done:
			cancel()
		case <-quit:
		}
	}()
	return func() bool {
		close(quit)
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
}

// StreamWindow implements per-stream credit-based flow control.
//
// Sender side: Consume blocks until credit is available (up to ConsumeTimeout)
// using a golang.org/x/sync/semaphore — no busy polling, context-aware
// cancellation. Every byte is charged, whatever the size of the frame.
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
// Alternative shape, not built: drop the credit counter entirely and gate
// Send on write-queue depth (QUIC/HTTP/2 style offsets). Worth considering
// only if credit-based flow control proves inadequate.
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

	// currentWindow is the effective max window after any Grow/Shrink
	// adjustments. Tracked separately from initialSize so that autogrant
	// capping (ReceiverConsume) reflects the live target, not the
	// construction-time value. Always equals maxSize - initialDeficit.
	currentWindow int64

	// Receive-side accounting — drives auto-grant decisions.
	// recvCredit represents credit we have extended to the sender but that has
	// not yet been consumed by the data arriving at us. It decreases as we
	// receive data (the sender is consuming credit we granted earlier) and
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
	grantsEmitted  int64
	grantsReceived int64

	// Auto-tuning hints — advisory data an auto-tuner reads via Stats().
	// Updated from Consume/ApplyUpdate hot paths, guarded by mu.
	peakOutstanding int64         // max dataOutstanding observed since last tune
	charged         int64         // bytes sends have charged over the window's life, what Charged reports
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

	// creditAbuseSince records the start of the CURRENT
	// CreditAbuseDuration window for a sustained
	// (grantsEmitted - consumed) / grantsEmitted > CreditAbuseRatio
	// imbalance. Zero when the gap is healthy. Re-anchored to the
	// firing time when CheckCreditAbuse fires so persistent abuse
	// keeps accruing score on each subsequent full window.
	creditAbuseSince time.Time

	// grantStarveHist (optional) is a session-shared DurationHist that
	// records how long Consume blocked acquiring credit. Set via
	// SetGrantStarveHist by the owning session at stream construction;
	// nil means Consume skips recording. Stored as a raw pointer (NOT
	// atomic.Pointer) because the field is wired once at construction
	// and never swapped after — concurrent reads of an immutable
	// pointer are safe without atomic protection.
	//
	// Only a Consume whose non-blocking TryAcquire failed is recorded
	// (ConsumeUntil's contended path); recording every uncontended
	// success would dominate the distribution with sub-microsecond
	// samples and bury the actual starvation signal.
	grantStarveHist *metrics.DurationHist
}

// CreditAbuseRatio is the (grantsEmitted - consumed) / grantsEmitted
// threshold above which a stream is considered to be hoarding credit
// — the receiver extended bandwidth via WINDOW_UPDATE but the peer is
// not delivering data to consume it. Mirrors the sustained-imbalance
// definition the abuse scorer uses for other flow-control
// anomalies.
const CreditAbuseRatio = 0.5

// CreditAbuseDuration is how long the (grantsEmitted vs consumed) gap
// must persist past CreditAbuseRatio before CheckCreditAbuse reports
// abuse. 30 s: short-lived imbalances under bursty traffic are normal; a
// persistent imbalance for a full half-minute on an active stream is
// the anomalous signal, which the noise adapter's reliabilityTick
// reports as abuse.ReasonFlowControlAbuse.
const CreditAbuseDuration = 30 * time.Second

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
	if initialCredit < MinGuaranteedWindow {
		initialCredit = MinGuaranteedWindow
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

// SetGrantStarveHist wires the session-shared grant-starvation histogram
// into this stream window. Consume records the wall-clock it spent blocked
// on the credit semaphore into the histogram, skipping every call whose
// non-blocking acquire succeeds (the uncontended fast path); the owning
// noise session
// reads its percentiles into SessionMetrics.GrantStarveP50Us/P99Us. Pass
// nil to disable recording (default for windows constructed via
// NewStreamWindow).
//
// Must be called BEFORE Consume sees concurrent traffic. The field is
// wired once at session-create time and never swapped — concurrent
// reads of an immutable pointer don't need atomic protection.
func (w *StreamWindow) SetGrantStarveHist(h *metrics.DurationHist) {
	w.grantStarveHist = h
}

// TryConsume attempts a non-blocking credit acquire (the fast path only) and
// returns true if credit was available and consumed, false otherwise — it
// NEVER blocks, where the blocking Consume could stall a send for the full
// ConsumeTimeout (~10s) on a drained window. Only tests call it in this
// repository: noiseStream.Send uses Consume and a byte-stream session keeps no
// window.
func (w *StreamWindow) TryConsume(n int64) bool {
	if n <= 0 {
		return true
	}
	if w.sem.TryAcquire(n) {
		w.mu.Lock()
		w.dataOutstanding += n
		w.charged += n
		if w.dataOutstanding > w.peakOutstanding {
			w.peakOutstanding = w.dataOutstanding
		}
		w.mu.Unlock()
		return true
	}
	return false
}

// Consume reserves n bytes of sender credit before a Send, blocking until
// credit is available and honouring ctx cancellation. After ConsumeTimeout
// with no credit the call fails with ErrCreditExhausted, which the adapter's
// noiseStream.Send wraps (errors.Is matches) and returns to its caller as typed
// backpressure.
func (w *StreamWindow) Consume(ctx context.Context, n int64) error {
	return w.ConsumeUntil(ctx, n, nil)
}

// ConsumeUntil is Consume whose wait also ends when done closes, answering
// ErrWaitEnded with nothing charged. noiseStream.Send passes its session's close
// signal: a closed session's write loop has stopped and no grant will reach the
// window, so a Send waiting for credit when its session closes returns the close at
// once, typed as aether.ErrSessionClosed, rather than waiting out ConsumeTimeout and
// reading as backpressure.
func (w *StreamWindow) ConsumeUntil(ctx context.Context, n int64, done <-chan struct{}) error {
	if n <= 0 {
		return nil
	}

	// Fast path: try a non-blocking acquire first. When credit is
	// immediately available (the common case on a healthy stream) we
	// skip both the timeout-context construction and the entire
	// grant-starvation timing instrumentation. The wired-histogram cost
	// is therefore zero on uncontended Consume calls — the fast-path
	// skip SetGrantStarveHist documents.
	if w.sem.TryAcquire(n) {
		w.mu.Lock()
		w.dataOutstanding += n
		w.charged += n
		if w.dataOutstanding > w.peakOutstanding {
			w.peakOutstanding = w.dataOutstanding
		}
		outstanding := w.dataOutstanding
		w.mu.Unlock()
		dbgFlow.Printf("Consume FAST n=%d outstanding=%d avail=%d", n, outstanding, w.currentWindow-outstanding)
		return nil
	}

	acquireCtx, cancel := context.WithTimeout(ctx, ConsumeTimeout)
	defer cancel()

	// Contended path: TryAcquire above already failed so we KNOW this
	// Consume is going to block on real credit-starvation. Time it
	// unconditionally and record on BOTH success and timeout paths —
	// every sample here represents real semaphore contention worth
	// surfacing in grantStarveHist. No floor gate: the worst-case ~10s timeout
	// path is the single most important starvation signal an operator
	// needs in a credit-deadlock dashboard, and the fast-path skip
	// above already filters out uncontended noise.
	var starveStart time.Time
	if w.grantStarveHist != nil {
		starveStart = time.Now()
	}

	stopWatch := endWaitOn(done, cancel)
	err := w.sem.Acquire(acquireCtx, n)
	ended := stopWatch()

	if w.grantStarveHist != nil {
		w.grantStarveHist.Record(time.Since(starveStart))
	}

	if err != nil && ended {
		return fmt.Errorf("aether flow: stream credit wait for %d: %w", n, ErrWaitEnded)
	}
	if err != nil {
		avail := w.Available()
		dbgFlow.Printf("Consume TIMEOUT need=%d have=%d outstanding=%d maxSize=%d",
			n, avail, w.dataOutstanding, w.maxSize)
		return fmt.Errorf("aether flow: insufficient stream credit after %s (need %d, have %d): %w: %w",
			ConsumeTimeout, n, avail, ErrCreditExhausted, err)
	}

	w.mu.Lock()
	w.dataOutstanding += n
	w.charged += n
	if w.dataOutstanding > w.peakOutstanding {
		w.peakOutstanding = w.dataOutstanding
	}
	outstanding := w.dataOutstanding
	w.mu.Unlock()
	dbgFlow.Printf("Consume OK n=%d outstanding=%d avail=%d", n, outstanding, w.currentWindow-outstanding)
	return nil
}

// ReleaseUnsent returns credit reserved by Consume that never reached
// the wire. Use when a Send-path layer downstream of stream-window
// Consume rejects the bytes (e.g. connection-window Consume fails,
// frame serialisation errors, the stream is closed mid-Send).
//
// Without this release path, every failed Send permanently shrinks
// the stream's effective window by its payload — a credit leak:
// Consume then fails with insufficient stream credit although the
// peer owes nothing. The peer never generates a WINDOW_UPDATE for
// bytes it never received, so nothing else recovers the credit.
//
// Capped at dataOutstanding so over-release composes safely with
// ApplyUpdate — whichever release runs first returns its share; later
// releases find dataOutstanding already reduced and become no-ops.
func (w *StreamWindow) ReleaseUnsent(n int64) {
	if n <= 0 {
		return
	}
	w.mu.Lock()
	release := n
	if release > w.dataOutstanding {
		release = w.dataOutstanding
	}
	w.dataOutstanding -= release
	w.charged -= release
	w.mu.Unlock()
	if release > 0 {
		w.sem.Release(release)
	}
	dbgFlow.Printf("ReleaseUnsent requested=%d released=%d", n, release)
}

// Charged returns the bytes this window's sends have charged over its life, less
// what ReleaseUnsent gave back for bytes that never reached the wire: what a RESET
// states as its stream's charge (aether.ResetPayload.Charged). Charged minus what
// ReleaseAll reports is what grants had returned by then.
func (w *StreamWindow) Charged() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.charged
}

// ReleaseAll returns every outstanding byte to the window and reports how many,
// for a stream a RESET has ended: no grant for these bytes will reach this
// window. noiseStream.releaseInFlight calls it once the stream's credit is
// settled (ReleaseAllCharged, which the RESET's settlement reads instead), for
// what Sends charged after that settlement and return to the connection window
// themselves. A Send blocked in Consume wakes and finds the stream's state
// closed. Idempotent: a second call reports what was charged since, so 0 on a
// stream that has left.
func (w *StreamWindow) ReleaseAll() int64 {
	w.mu.Lock()
	n := w.dataOutstanding
	w.dataOutstanding = 0
	w.mu.Unlock()
	if n > 0 {
		w.sem.Release(n)
	}
	return n
}

// ReleaseAllCharged is ReleaseAll that also returns Charged as it stood at the same
// instant: both counts are read and the outstanding bytes released under one hold of
// the window's lock, so no Consume or ReleaseUnsent falls between them and charged
// minus released is exactly what grants had returned by then. noiseStream's RESET
// settlement (settleCharges) reads the pair against the connection charge its Sends
// recorded, so a stream charge whose Send has not charged the connection yet is not
// returned to the connection window as if it had.
func (w *StreamWindow) ReleaseAllCharged() (released, charged int64) {
	w.mu.Lock()
	released, charged = w.dataOutstanding, w.charged
	w.dataOutstanding = 0
	w.mu.Unlock()
	if released > 0 {
		w.sem.Release(released)
	}
	return released, charged
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
	// Read under w.mu: GrowWindow and ShrinkWindow (the session's autotune tick)
	// write initialDeficit under it, and the log's arguments are evaluated
	// whether or not the debug channel is on.
	avail := w.maxSize - w.initialDeficit - outstanding
	w.mu.Unlock()
	if granted > 0 {
		w.sem.Release(granted)
	}
	dbgFlow.Printf("ApplyUpdate cumulative=%d delta=%d granted=%d outstanding=%d avail=%d",
		credit, delta, granted, outstanding, avail)
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

// Outstanding returns the bytes the sender has Consume()d that no grant has
// returned yet: on the wire, or held by the peer's receive queue until its
// consumer takes them, in what Consume charges: the count its Send passes
// (the adapter's noiseStream.Send passes the plaintext length plus a fixed
// per-message cost), not the frame wire bytes a CEBytes claim counts.
func (w *StreamWindow) Outstanding() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dataOutstanding
}

// CheckCreditAbuse reports whether the stream is currently exhibiting
// a sustained credit-hoarding pattern: the receiver has granted more
// bandwidth than the peer is consuming, and the imbalance has lasted
// at least CreditAbuseDuration.
//
// Persistent abuse keeps accruing score: once an imbalance window
// fires, the anchor advances by another CreditAbuseDuration so the
// next fire happens after the next full window of sustained
// imbalance. The single-fire-then-quiet semantics would otherwise
// limit a hostile peer to one +8 score increment per imbalance
// episode regardless of duration — well below the 100-point abuse
// threshold (see abuse.ReasonFlowControlAbuse weight).
//
// Returns true at most once per CreditAbuseDuration window for the
// SAME ongoing imbalance, so adapter callers can invoke this on every
// reliability tick without flooding the abuse scorer.
//
// Internally tracks creditAbuseSince so the duration is measured across
// multiple calls without per-stream timer machinery. The window resets
// to zero whenever the imbalance recovers below CreditAbuseRatio,
// so transient spikes don't accumulate toward the duration.
//
// Safe to call from any goroutine.
func (w *StreamWindow) CheckCreditAbuse() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.grantsEmitted <= 0 {
		// No grants ever issued — no imbalance possible. Reset any
		// stale window-start so we don't fire when grants resume.
		w.creditAbuseSince = time.Time{}
		return false
	}

	gap := w.grantsEmitted - w.consumed
	if gap <= 0 {
		w.creditAbuseSince = time.Time{}
		return false
	}
	ratio := float64(gap) / float64(w.grantsEmitted)
	if ratio <= CreditAbuseRatio {
		w.creditAbuseSince = time.Time{}
		return false
	}

	now := time.Now()
	if w.creditAbuseSince.IsZero() {
		w.creditAbuseSince = now
		return false
	}
	if now.Sub(w.creditAbuseSince) >= CreditAbuseDuration {
		// Re-anchor the window so persistent abuse fires once per
		// CreditAbuseDuration. A peer that keeps hoarding for an hour
		// will produce 120 fires (one every 30s) — well past the
		// 100-point abuse threshold even at weight 8.
		w.creditAbuseSince = now
		return true
	}
	return false
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
	// Stop at MinGuaranteedWindow, the credit a sender can always count on
	// for one small message once what is outstanding has been consumed.
	w.mu.Lock()
	if n > w.currentWindow-MinGuaranteedWindow {
		n = w.currentWindow - MinGuaranteedWindow
	}
	w.mu.Unlock()
	if n <= 0 {
		return 0
	}

	// Try to acquire the shrink amount from the semaphore (reclaiming the
	// free portion). If in-flight data plus the shrink amount would exceed
	// capacity, TryAcquire fails and we return 0.
	if !w.sem.TryAcquire(n) {
		return 0
	}
	w.mu.Lock()
	w.initialDeficit += n
	w.currentWindow -= n
	// Maintain the recvCredit <= currentWindow invariant. grantLocked
	// suppresses WINDOW_UPDATE emission when recvCredit > currentWindow,
	// and ReceiverConsume is the only path that decrements recvCredit —
	// so a shrunk-while-idle stream can sit indefinitely with the sender
	// stalled waiting for a grant that never emits. Clamp here so the
	// post-shrink state always satisfies recvCredit <= currentWindow
	// and grantLocked can resume emitting updates.
	if w.recvCredit > w.currentWindow {
		w.recvCredit = w.currentWindow
	}
	dbgFlow.Printf("ShrinkWindow by=%d currentWindow=%d deficit=%d recvCredit=%d", n, w.currentWindow, w.initialDeficit, w.recvCredit)
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
