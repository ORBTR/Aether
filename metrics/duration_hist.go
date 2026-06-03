/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package metrics holds tiny, allocation-free sample histograms used by
// the aether session for observability instrumentation.
//
// All types in this package follow the same pattern: a fixed-capacity
// ring buffer recording recent samples under a single mutex, with
// percentile readouts computed lazily at Snapshot/Percentile time by
// copying-and-sorting the buffer. Per-Record cost is O(1) and
// allocation-free; percentile reads are O(N log N) at N ≤ 256 (~few µs).
//
// Mirrors the histogram pattern in aether/rtt.Estimator without the
// EMA / RTO machinery — these are pure distribution histograms, not
// signal estimators.
package metrics

import (
	"sort"
	"sync"
	"time"
)

// histRingSize is the fixed capacity of every histogram ring buffer in
// this package. 256 samples produce stable p50/p95/p99 readouts on
// streams seeing ~10+ samples/s (~25s window). Memory cost per histogram
// is 256 * 8 = 2 KiB — small enough to keep multiple per session.
const histRingSize = 256

// DurationHist is a fixed-capacity ring buffer of recent time.Duration
// samples (stored internally as microseconds for compact representation).
// Safe for concurrent use; reads share the same mutex as writes.
//
// Record cost: one mutex acquire + one int64 write — well under 1µs on
// modern hardware. No allocations on the hot path.
//
// PercentileSnapshot cost: copy + sort up to histRingSize int64s — a few
// microseconds. Callers should only invoke at metric-publication time,
// not on the hot path.
type DurationHist struct {
	mu    sync.Mutex
	buf   [histRingSize]int64 // microseconds
	head  int
	count int
}

// Record appends a sample to the ring buffer. Negative or zero durations
// are dropped (no-op) so callers can pass `time.Since(start)` without
// pre-clamping clock-skew negatives.
func (h *DurationHist) Record(d time.Duration) {
	if d <= 0 {
		return
	}
	us := d.Microseconds()
	if us <= 0 {
		// Sub-microsecond samples still record as 1µs so the ring isn't
		// polluted with zero "no sample" entries that PercentileSnapshot
		// can't distinguish from an empty slot.
		us = 1
	}
	h.mu.Lock()
	h.buf[h.head] = us
	h.head = (h.head + 1) % histRingSize
	if h.count < histRingSize {
		h.count++
	}
	h.mu.Unlock()
}

// PercentileSnapshot returns the p50/p95/p99 percentile samples in
// microseconds (matching the storage unit). Returns (0, 0, 0) if no
// samples have been recorded yet. Copies + sorts the buffer once per
// call.
//
// Nearest-rank percentiles (not interpolated) — each return value is
// one of the actual recorded samples.
func (h *DurationHist) PercentileSnapshot() (p50, p95, p99 int64) {
	buf := h.copy()
	if len(buf) == 0 {
		return 0, 0, 0
	}
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	n := len(buf)
	p50 = buf[(50*(n-1))/100]
	p95 = buf[(95*(n-1))/100]
	p99 = buf[(99*(n-1))/100]
	return p50, p95, p99
}

// Count returns the number of samples currently retained (≤ histRingSize).
// Operators can use this to gate display: a histogram with very few
// samples produces unstable percentiles.
func (h *DurationHist) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// copy returns a fresh slice containing the valid portion of the ring
// buffer. Order is irrelevant — callers always sort.
func (h *DurationHist) copy() []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return nil
	}
	out := make([]int64, h.count)
	copy(out, h.buf[:h.count])
	return out
}

// PermilleRing is a fixed-capacity ring buffer of uint32 per-mille
// (0..1000) ratio samples used for OBS-10 cwnd-utilisation. Cheaper than
// DurationHist (uint32 vs int64), no negative-sample guard.
//
// Used by writeLoop to record inFlight/cwnd ratios on a sampled subset
// of frames (e.g. every 16th) — the ring saturates quickly even at low
// sample rates and the percentile readout describes how heavily the
// congestion window is utilised on a sustained basis.
type PermilleRing struct {
	mu    sync.Mutex
	buf   [histRingSize]uint32
	head  int
	count int
}

// Record appends a per-mille sample. Values above 1000 are clamped to
// 1000 so a transient inFlight > cwnd race (possible during the tiny
// window between OnSend and OnAck) doesn't produce nonsensical
// percentile readouts.
func (r *PermilleRing) Record(v uint32) {
	if v > 1000 {
		v = 1000
	}
	r.mu.Lock()
	r.buf[r.head] = v
	r.head = (r.head + 1) % histRingSize
	if r.count < histRingSize {
		r.count++
	}
	r.mu.Unlock()
}

// PercentileSnapshot returns the p50/p99 per-mille samples. Returns
// (0, 0) if no samples have been recorded yet. p95 is not surfaced —
// p50 and p99 are sufficient for cwnd-utilisation triage (typical vs
// tail).
func (r *PermilleRing) PercentileSnapshot() (p50, p99 uint32) {
	buf := r.copy()
	if len(buf) == 0 {
		return 0, 0
	}
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	n := len(buf)
	p50 = buf[(50*(n-1))/100]
	p99 = buf[(99*(n-1))/100]
	return p50, p99
}

// Count returns the number of samples currently retained.
func (r *PermilleRing) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func (r *PermilleRing) copy() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil
	}
	out := make([]uint32, r.count)
	copy(out, r.buf[:r.count])
	return out
}

// Uint32Ring is a fixed-capacity ring buffer of raw uint32 samples used
// for OBS-9 scheduler queue-depth sampling. Unlike PermilleRing it does
// not clamp to 1000 — depth values are unbounded in principle (any
// number of frames may queue across all streams) so the caller-supplied
// value is recorded verbatim.
//
// Used by the scheduler to record per-Wake / per-Park queue-depth
// observations. The p50/p99 readout tells operators whether work piles
// up behind the writeLoop (sustained high depth) or is consumed as fast
// as it arrives (depth near zero). Per-Record cost is one mutex acquire
// + one uint32 store — well under 100ns on modern hardware.
type Uint32Ring struct {
	mu    sync.Mutex
	buf   [histRingSize]uint32
	head  int
	count int
}

// Record appends a uint32 sample to the ring buffer.
func (r *Uint32Ring) Record(v uint32) {
	r.mu.Lock()
	r.buf[r.head] = v
	r.head = (r.head + 1) % histRingSize
	if r.count < histRingSize {
		r.count++
	}
	r.mu.Unlock()
}

// PercentileSnapshot returns the p50/p99 samples. Returns (0, 0) if no
// samples have been recorded yet. p95 is not surfaced — p50 and p99 are
// sufficient for scheduler-depth triage (typical vs tail).
func (r *Uint32Ring) PercentileSnapshot() (p50, p99 uint32) {
	buf := r.copy()
	if len(buf) == 0 {
		return 0, 0
	}
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	n := len(buf)
	p50 = buf[(50*(n-1))/100]
	p99 = buf[(99*(n-1))/100]
	return p50, p99
}

// Count returns the number of samples currently retained.
func (r *Uint32Ring) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func (r *Uint32Ring) copy() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil
	}
	out := make([]uint32, r.count)
	copy(out, r.buf[:r.count])
	return out
}
