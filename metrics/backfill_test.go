/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package metrics

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// DurationHist
// ---------------------------------------------------------------------------

// An empty histogram must report zero count and a zero-valued snapshot so
// callers can gate display on Count without special-casing the nil buffer.
func TestDurationHist_Empty(t *testing.T) {
	var h DurationHist
	if c := h.Count(); c != 0 {
		t.Errorf("Count on empty: got %d, want 0", c)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("PercentileSnapshot on empty: got (%d, %d, %d), want (0, 0, 0)", p50, p95, p99)
	}
}

// Record N distinct microsecond samples in DESCENDING order (so the test
// also proves the internal sort, not just insertion order) and assert the
// exact nearest-rank percentiles. For sorted 1..100 (n=100) the indices are
// (pct*(n-1))/100: p50=idx49=50, p95=idx94=95, p99=idx98=99.
func TestDurationHist_RecordAndPercentiles(t *testing.T) {
	var h DurationHist
	for i := 100; i >= 1; i-- { // descending input
		h.Record(time.Duration(i) * time.Microsecond)
	}
	if c := h.Count(); c != 100 {
		t.Fatalf("Count: got %d, want 100", c)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 50 {
		t.Errorf("p50: got %d, want 50", p50)
	}
	if p95 != 95 {
		t.Errorf("p95: got %d, want 95", p95)
	}
	if p99 != 99 {
		t.Errorf("p99: got %d, want 99", p99)
	}
}

// Non-positive durations are dropped at the guard so callers may pass a raw
// time.Since(start) with clock-skew negatives without polluting the ring.
func TestDurationHist_DropsNonPositive(t *testing.T) {
	var h DurationHist
	h.Record(0)
	h.Record(-1 * time.Microsecond)
	h.Record(time.Duration(-500))
	if c := h.Count(); c != 0 {
		t.Errorf("non-positive samples recorded: Count=%d, want 0", c)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("snapshot after only non-positive: got (%d, %d, %d), want zeros", p50, p95, p99)
	}

	// A single valid sample after the dropped ones must be the only entry.
	h.Record(42 * time.Microsecond)
	if c := h.Count(); c != 1 {
		t.Fatalf("after one valid sample: Count=%d, want 1", c)
	}
	if p50, _, _ = h.PercentileSnapshot(); p50 != 42 {
		t.Errorf("p50 after one valid sample: got %d, want 42", p50)
	}
}

// A positive but sub-microsecond duration truncates to 0µs; the code clamps
// it up to 1µs rather than storing a 0 that PercentileSnapshot could not
// distinguish from an unused slot.
func TestDurationHist_SubMicrosecondClampsToOne(t *testing.T) {
	var h DurationHist
	h.Record(500 * time.Nanosecond) // >0 but .Microseconds() == 0
	if c := h.Count(); c != 1 {
		t.Fatalf("sub-µs sample not recorded: Count=%d, want 1", c)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 1 || p95 != 1 || p99 != 1 {
		t.Errorf("sub-µs clamp: got (%d, %d, %d), want (1, 1, 1)", p50, p95, p99)
	}
}

// Filling the ring beyond capacity must cap Count at histRingSize and fully
// evict the oldest lap. After 256 samples of 10µs then a full second lap of
// 256 samples of 20µs, every retained sample is 20µs.
func TestDurationHist_RingFullyEvictsOldLap(t *testing.T) {
	var h DurationHist
	for i := 0; i < histRingSize; i++ {
		h.Record(10 * time.Microsecond)
	}
	for i := 0; i < histRingSize; i++ {
		h.Record(20 * time.Microsecond)
	}
	if c := h.Count(); c != histRingSize {
		t.Fatalf("Count after 2 full laps: got %d, want %d", c, histRingSize)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 20 || p95 != 20 || p99 != 20 {
		t.Errorf("old lap not evicted: got (%d, %d, %d), want (20, 20, 20)", p50, p95, p99)
	}
}

// Partial wraparound leaves a mixed distribution: after 256×1µs then 100×1000µs,
// slots 0..99 hold 1000 and slots 100..255 hold 1 (156 samples), so the sorted
// buffer is [1×156, 1000×100]. Nearest-rank on n=256: p50=idx127=1 (still in the
// 1µs region), p95=idx242=1000, p99=idx252=1000.
func TestDurationHist_PartialWraparoundDistribution(t *testing.T) {
	var h DurationHist
	for i := 0; i < histRingSize; i++ {
		h.Record(1 * time.Microsecond)
	}
	for i := 0; i < 100; i++ {
		h.Record(1000 * time.Microsecond)
	}
	if c := h.Count(); c != histRingSize {
		t.Fatalf("Count: got %d, want %d", c, histRingSize)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != 1 {
		t.Errorf("p50: got %d, want 1 (bulk still 1µs)", p50)
	}
	if p95 != 1000 {
		t.Errorf("p95: got %d, want 1000 (tail is the new 1000µs samples)", p95)
	}
	if p99 != 1000 {
		t.Errorf("p99: got %d, want 1000", p99)
	}
}

// Concurrent Record calls must not race and must cap Count at histRingSize.
// All samples are the same value so the deterministic snapshot is (v,v,v)
// regardless of interleaving — no wall-clock timing dependence.
func TestDurationHist_ConcurrentRecord(t *testing.T) {
	var h DurationHist
	const (
		goroutines     = 16
		perGoroutine   = 64 // 16*64 = 1024 total, well over histRingSize
		sampleMicros   = 7
	)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				h.Record(sampleMicros * time.Microsecond)
			}
		}()
	}
	wg.Wait()

	if c := h.Count(); c != histRingSize {
		t.Errorf("Count after concurrent overfill: got %d, want %d", c, histRingSize)
	}
	p50, p95, p99 := h.PercentileSnapshot()
	if p50 != sampleMicros || p95 != sampleMicros || p99 != sampleMicros {
		t.Errorf("uniform-sample snapshot: got (%d, %d, %d), want (%d, %d, %d)",
			p50, p95, p99, sampleMicros, sampleMicros, sampleMicros)
	}
}

// ---------------------------------------------------------------------------
// PermilleRing
// ---------------------------------------------------------------------------

func TestPermilleRing_Empty(t *testing.T) {
	var r PermilleRing
	if c := r.Count(); c != 0 {
		t.Errorf("Count on empty: got %d, want 0", c)
	}
	if p50, p99 := r.PercentileSnapshot(); p50 != 0 || p99 != 0 {
		t.Errorf("snapshot on empty: got (%d, %d), want (0, 0)", p50, p99)
	}
}

// Values above 1000 per-mille are clamped to 1000 so a transient inFlight>cwnd
// race can't produce out-of-range percentile readouts.
func TestPermilleRing_ClampsAboveThousand(t *testing.T) {
	var r PermilleRing
	r.Record(2000)
	r.Record(1001)
	r.Record(5000)
	if c := r.Count(); c != 3 {
		t.Fatalf("Count: got %d, want 3", c)
	}
	// Every stored value clamped to the 1000 ceiling.
	p50, p99 := r.PercentileSnapshot()
	if p50 != 1000 || p99 != 1000 {
		t.Errorf("clamp: got (%d, %d), want (1000, 1000)", p50, p99)
	}

	// Exactly 1000 is a legal value and passes through unchanged.
	var r2 PermilleRing
	r2.Record(1000)
	if p50, p99 := r2.PercentileSnapshot(); p50 != 1000 || p99 != 1000 {
		t.Errorf("boundary 1000: got (%d, %d), want (1000, 1000)", p50, p99)
	}
}

// Record 1..100 (descending input to exercise the sort). Sorted n=100:
// p50=idx49=50, p99=idx98=99. p95 is intentionally not surfaced by this type.
func TestPermilleRing_Percentiles(t *testing.T) {
	var r PermilleRing
	for v := 100; v >= 1; v-- {
		r.Record(uint32(v))
	}
	p50, p99 := r.PercentileSnapshot()
	if p50 != 50 {
		t.Errorf("p50: got %d, want 50", p50)
	}
	if p99 != 99 {
		t.Errorf("p99: got %d, want 99", p99)
	}
}

// ---------------------------------------------------------------------------
// Uint32Ring
// ---------------------------------------------------------------------------

func TestUint32Ring_Empty(t *testing.T) {
	var r Uint32Ring
	if c := r.Count(); c != 0 {
		t.Errorf("Count on empty: got %d, want 0", c)
	}
	if p50, p99 := r.PercentileSnapshot(); p50 != 0 || p99 != 0 {
		t.Errorf("snapshot on empty: got (%d, %d), want (0, 0)", p50, p99)
	}
}

// Unlike PermilleRing, Uint32Ring records queue-depth verbatim with NO clamp —
// large values must survive intact (this is the defining behavioural
// difference between the two uint32 rings).
func TestUint32Ring_NoClamp(t *testing.T) {
	var r Uint32Ring
	r.Record(5000)
	r.Record(1000000)
	if c := r.Count(); c != 2 {
		t.Fatalf("Count: got %d, want 2", c)
	}
	// Sorted [5000, 1000000], n=2: p50=idx0=5000, p99=idx0=5000.
	p50, p99 := r.PercentileSnapshot()
	if p50 != 5000 {
		t.Errorf("p50: got %d, want 5000 (no clamp)", p50)
	}
	if p99 != 5000 {
		t.Errorf("p99: got %d, want 5000", p99)
	}

	// A single large sample is returned unclamped at every percentile.
	var r2 Uint32Ring
	r2.Record(1000000)
	if p50, p99 := r2.PercentileSnapshot(); p50 != 1000000 || p99 != 1000000 {
		t.Errorf("single large sample: got (%d, %d), want (1000000, 1000000)", p50, p99)
	}
}

// Record 1..100 descending; sorted n=100 gives p50=50, p99=99.
func TestUint32Ring_Percentiles(t *testing.T) {
	var r Uint32Ring
	for v := 100; v >= 1; v-- {
		r.Record(uint32(v))
	}
	p50, p99 := r.PercentileSnapshot()
	if p50 != 50 {
		t.Errorf("p50: got %d, want 50", p50)
	}
	if p99 != 99 {
		t.Errorf("p99: got %d, want 99", p99)
	}
}

// Ring wraparound caps Count and evicts the oldest lap for Uint32Ring too.
func TestUint32Ring_RingFullyEvictsOldLap(t *testing.T) {
	var r Uint32Ring
	for i := 0; i < histRingSize; i++ {
		r.Record(11)
	}
	for i := 0; i < histRingSize; i++ {
		r.Record(22)
	}
	if c := r.Count(); c != histRingSize {
		t.Fatalf("Count after 2 laps: got %d, want %d", c, histRingSize)
	}
	if p50, p99 := r.PercentileSnapshot(); p50 != 22 || p99 != 22 {
		t.Errorf("old lap not evicted: got (%d, %d), want (22, 22)", p50, p99)
	}
}
