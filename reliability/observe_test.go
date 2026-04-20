/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"testing"
	"time"
)

func TestObserveEngine_InOrderDelivery(t *testing.T) {
	o := NewObserveEngine()
	now := time.Now()
	o.RecordReceive(1, 100, now)
	o.RecordReceive(2, 200, now.Add(time.Millisecond))
	o.RecordReceive(3, 150, now.Add(2*time.Millisecond))

	m := o.Metrics()
	if m.PacketsReceived != 3 {
		t.Fatalf("packets: got %d, want 3", m.PacketsReceived)
	}
	if m.BytesReceived != 450 {
		t.Fatalf("bytes: got %d, want 450", m.BytesReceived)
	}
	if m.HighestSeqNo != 3 {
		t.Fatalf("highest: got %d, want 3", m.HighestSeqNo)
	}
	if m.GapCount != 0 {
		t.Fatalf("gaps: got %d, want 0", m.GapCount)
	}
	if m.ReorderCount != 0 {
		t.Fatalf("reorders: got %d, want 0", m.ReorderCount)
	}
}

func TestObserveEngine_DetectsGaps(t *testing.T) {
	o := NewObserveEngine()
	now := time.Now()
	o.RecordReceive(1, 100, now)
	o.RecordReceive(3, 100, now.Add(time.Millisecond))   // gap: 2 missing
	o.RecordReceive(5, 100, now.Add(2*time.Millisecond)) // gap: 4 missing

	m := o.Metrics()
	if m.GapCount != 2 {
		t.Fatalf("gaps: got %d, want 2", m.GapCount)
	}
}

func TestObserveEngine_DetectsReorder(t *testing.T) {
	o := NewObserveEngine()
	now := time.Now()
	o.RecordReceive(1, 100, now)
	o.RecordReceive(3, 100, now.Add(time.Millisecond))
	o.RecordReceive(2, 100, now.Add(2*time.Millisecond)) // reorder: arrived after 3

	m := o.Metrics()
	if m.ReorderCount != 1 {
		t.Fatalf("reorders: got %d, want 1", m.ReorderCount)
	}
	if m.MaxReorderDistance != 2 {
		// expectedSeq=4 after receiving 3, then 2 arrives → distance = 4-2 = 2
		t.Fatalf("max reorder distance: got %d, want 2", m.MaxReorderDistance)
	}
}

func TestObserveEngine_LossEstimate(t *testing.T) {
	o := NewObserveEngine()
	now := time.Now()
	for _, seq := range []uint32{1, 2, 3, 5, 6, 7} {
		o.RecordReceive(seq, 100, now)
	}
	m := o.Metrics()
	// 6 received, highest=7 → expected=7 → 1 missing → 1000*1/7 ≈ 142 permille
	if m.LossEstimatePermille < 100 || m.LossEstimatePermille > 200 {
		t.Fatalf("loss estimate: got %d permille, want ~143", m.LossEstimatePermille)
	}
}

func TestObserveEngine_Throughput(t *testing.T) {
	o := NewObserveEngine()
	start := time.Now()
	for i := uint32(1); i <= 10; i++ {
		o.RecordReceive(i, 1000, start.Add(time.Duration(i)*time.Millisecond))
	}
	m := o.Metrics()
	if m.BytesReceived != 10000 {
		t.Fatalf("bytes: got %d, want 10000", m.BytesReceived)
	}
	if m.HighestSeqNo != 10 {
		t.Fatalf("highest: got %d, want 10", m.HighestSeqNo)
	}
}

func TestObserveEngine_Reset(t *testing.T) {
	o := NewObserveEngine()
	o.RecordReceive(1, 100, time.Now())
	o.RecordReceive(5, 200, time.Now())
	o.Reset()
	m := o.Metrics()
	if m.PacketsReceived != 0 {
		t.Fatalf("after reset packets: got %d, want 0", m.PacketsReceived)
	}
	if m.GapCount != 0 {
		t.Fatalf("after reset gaps: got %d, want 0", m.GapCount)
	}
}

func TestObserveEngine_Jitter(t *testing.T) {
	o := NewObserveEngine()
	base := time.Now()
	// Uniform 1ms spacing — jitter should converge toward 1000µs
	for i := uint32(1); i <= 20; i++ {
		o.RecordReceive(i, 100, base.Add(time.Duration(i)*time.Millisecond))
	}
	m := o.Metrics()
	// Jitter should be around 1000µs (1ms inter-arrival, EMA converges)
	if m.JitterUs < 500 || m.JitterUs > 1500 {
		t.Fatalf("jitter: got %dµs, want ~1000µs", m.JitterUs)
	}
}
