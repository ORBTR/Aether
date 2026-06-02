/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"bytes"
	"testing"
	"time"

	"github.com/ORBTR/aether/metrics"
)

func TestRecvWindow_InOrder(t *testing.T) {
	w := NewRecvWindow(64)

	delivered := w.Insert(0, []byte("a"))
	if len(delivered) != 1 || !bytes.Equal(delivered[0], []byte("a")) {
		t.Errorf("frame 0: got %v, want [a]", delivered)
	}

	delivered = w.Insert(1, []byte("b"))
	if len(delivered) != 1 || !bytes.Equal(delivered[0], []byte("b")) {
		t.Errorf("frame 1: got %v, want [b]", delivered)
	}

	if w.ExpectedSeqNo() != 2 {
		t.Errorf("expected: got %d, want 2", w.ExpectedSeqNo())
	}
}

func TestRecvWindow_OutOfOrder(t *testing.T) {
	w := NewRecvWindow(64)

	// Receive frame 2 first (out of order)
	delivered := w.Insert(2, []byte("c"))
	if len(delivered) != 0 {
		t.Error("out-of-order frame should not deliver")
	}
	if w.BufferedCount() != 1 {
		t.Errorf("buffered: got %d, want 1", w.BufferedCount())
	}

	// Receive frame 1 (still out of order, missing 0)
	delivered = w.Insert(1, []byte("b"))
	if len(delivered) != 0 {
		t.Error("still out-of-order, should not deliver")
	}

	// Receive frame 0 — should deliver 0, 1, 2 in order
	delivered = w.Insert(0, []byte("a"))
	if len(delivered) != 3 {
		t.Fatalf("expected 3 delivered, got %d", len(delivered))
	}
	if !bytes.Equal(delivered[0], []byte("a")) {
		t.Errorf("delivered[0]: got %q, want %q", delivered[0], "a")
	}
	if !bytes.Equal(delivered[1], []byte("b")) {
		t.Errorf("delivered[1]: got %q, want %q", delivered[1], "b")
	}
	if !bytes.Equal(delivered[2], []byte("c")) {
		t.Errorf("delivered[2]: got %q, want %q", delivered[2], "c")
	}
	if w.ExpectedSeqNo() != 3 {
		t.Errorf("expected: got %d, want 3", w.ExpectedSeqNo())
	}
}

func TestRecvWindow_Duplicate(t *testing.T) {
	w := NewRecvWindow(64)

	w.Insert(0, []byte("a"))
	delivered := w.Insert(0, []byte("a")) // duplicate
	if len(delivered) != 0 {
		t.Error("duplicate should not deliver")
	}
}

func TestRecvWindow_MissingRanges(t *testing.T) {
	w := NewRecvWindow(64)

	// Receive 2, 3, 5, 7, 8 — missing 0, 1, 4, 6
	w.Insert(2, []byte("c"))
	w.Insert(3, []byte("d"))
	w.Insert(5, []byte("f"))
	w.Insert(7, []byte("h"))
	w.Insert(8, []byte("i"))

	ranges := w.MissingRanges()
	// Should report received ranges: [2,3], [5,5], [7,8]
	if len(ranges) != 3 {
		t.Fatalf("expected 3 SACK blocks, got %d: %+v", len(ranges), ranges)
	}
	if ranges[0].Start != 2 || ranges[0].End != 3 {
		t.Errorf("block 0: got %+v, want {2, 3}", ranges[0])
	}
	if ranges[1].Start != 5 || ranges[1].End != 5 {
		t.Errorf("block 1: got %+v, want {5, 5}", ranges[1])
	}
	if ranges[2].Start != 7 || ranges[2].End != 8 {
		t.Errorf("block 2: got %+v, want {7, 8}", ranges[2])
	}
}

func TestRecvWindow_MissingRanges_Empty(t *testing.T) {
	w := NewRecvWindow(64)
	ranges := w.MissingRanges()
	if len(ranges) != 0 {
		t.Errorf("empty window should have no SACK blocks, got %d", len(ranges))
	}
}

func TestRecvWindow_MaxGap(t *testing.T) {
	w := NewRecvWindow(3) // small buffer

	// Fill buffer with out-of-order frames
	w.Insert(1, []byte("b"))
	w.Insert(2, []byte("c"))
	w.Insert(3, []byte("d"))

	// 4th out-of-order frame should be dropped (buffer full)
	w.Insert(4, []byte("e"))
	if w.BufferedCount() != 3 {
		t.Errorf("buffer should be capped at 3, got %d", w.BufferedCount())
	}
}

// TestRecvWindow_HOLHist verifies that the OBS-13 HOL-block histogram records
// a sample for each buffered frame that is flushed when its gap is filled, and
// records nothing for frames that arrive in order (zero HOL-block time).
func TestRecvWindow_HOLHist(t *testing.T) {
	var h metrics.DurationHist
	w := NewRecvWindow(64)
	w.SetHOLHist(&h)

	// Deliver frame 0 first. No reordering — histogram must stay empty.
	w.Insert(0, []byte("a"))
	if h.Count() != 0 {
		t.Fatalf("in-order frame should not record HOL sample; count=%d", h.Count())
	}

	// Buffer frames 2 and 3 (out of order — frame 1 is missing).
	w.Insert(2, []byte("c"))
	w.Insert(3, []byte("d"))
	if h.Count() != 0 {
		t.Fatalf("buffering frames must not record samples; count=%d", h.Count())
	}

	// Introduce a small sleep so buffered frames have a non-zero HOL age.
	time.Sleep(2 * time.Millisecond)

	// Deliver frame 1 — this triggers a flush of 2 and 3.
	delivered := w.Insert(1, []byte("b"))
	if len(delivered) != 3 {
		t.Fatalf("expected 3 delivered payloads, got %d", len(delivered))
	}

	// Two buffered frames (2 and 3) were flushed → two HOL samples.
	if h.Count() != 2 {
		t.Fatalf("expected 2 HOL samples after flush; count=%d", h.Count())
	}

	// Both samples should be positive (the buffered frames waited at least
	// the 2ms sleep before delivery).
	p50, _, _ := h.PercentileSnapshot()
	if p50 <= 0 {
		t.Errorf("HOL p50 must be positive; got %d µs", p50)
	}
}

// TestRecvWindow_HOLHist_NilSafe verifies that Insert does not panic when no
// histogram is wired (holHist == nil), which is the default for most streams.
func TestRecvWindow_HOLHist_NilSafe(t *testing.T) {
	w := NewRecvWindow(64)
	// No SetHOLHist call — holHist is nil.
	w.Insert(1, []byte("b"))
	// Filling the gap must not panic.
	w.Insert(0, []byte("a"))
}

func TestSortUint32(t *testing.T) {
	s := []uint32{5, 3, 8, 1, 2}
	sortUint32(s)
	expected := []uint32{1, 2, 3, 5, 8}
	for i, v := range s {
		if v != expected[i] {
			t.Errorf("index %d: got %d, want %d", i, v, expected[i])
		}
	}
}
