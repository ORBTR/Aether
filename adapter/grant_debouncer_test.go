//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package adapter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether/flow"
)

// fakeWindow mimics the grantable surface while letting tests count
// ReceiverConsume invocations and inspect the arguments. Real flow
// windows are covered by their own tests; here we only want to verify
// the debouncer's coalescing + immediate-flush + teardown semantics.
type fakeWindow struct {
	mu         sync.Mutex
	calls      int
	totalBytes int64
	// grant is the value returned from ReceiverConsume (cumulative grant
	// total). Zero means "no grant"; non-zero triggers a WINDOW_UPDATE
	// on the caller.
	grant int64
}

func (f *fakeWindow) ReceiverConsume(n int64) int64 {
	f.mu.Lock()
	f.calls++
	f.totalBytes += n
	g := f.grant
	f.mu.Unlock()
	return g
}

func (f *fakeWindow) snapshot() (calls int, total int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.totalBytes
}

// The coalesce window collapses a burst of small Record calls into a
// single ReceiverConsume + WINDOW_UPDATE.
func TestGrantDebouncer_CoalescesBurst(t *testing.T) {
	fw := &fakeWindow{grant: 4096} // any non-zero cumulative grant
	var updates atomic.Uint64
	var streamID uint64 = 42
	sendUpdate := func(sid uint64, credit uint64) {
		if sid != streamID {
			t.Errorf("send: streamID got %d, want %d", sid, streamID)
		}
		updates.Add(1)
	}

	d := newGrantDebouncer(fw, sendUpdate, streamID, 0 /* no immediate flush */)

	// 10 rapid back-to-back Record calls, small enough not to hit floor.
	for i := 0; i < 10; i++ {
		d.Record(128)
	}
	// Before the coalesce timer fires: zero ReceiverConsume + zero wire
	// updates. All 10 calls are coalesced into pending.
	if calls, total := fw.snapshot(); calls != 0 || total != 0 {
		t.Fatalf("pre-flush: unexpected ReceiverConsume state calls=%d total=%d", calls, total)
	}
	if u := updates.Load(); u != 0 {
		t.Fatalf("pre-flush: unexpected wire updates %d", u)
	}

	// Wait past the coalesce window (+ a little for scheduler jitter).
	time.Sleep(GrantCoalesceWindow + 50*time.Millisecond)

	calls, total := fw.snapshot()
	if calls != 1 {
		t.Errorf("post-flush: ReceiverConsume calls got %d, want 1 (coalesced)", calls)
	}
	if total != 10*128 {
		t.Errorf("post-flush: total bytes got %d, want %d", total, 10*128)
	}
	if u := updates.Load(); u != 1 {
		t.Errorf("post-flush: wire updates got %d, want 1 (coalesced into single WINDOW_UPDATE)", u)
	}
}

// Regression test for the immediate-flush escape hatch. When pending
// consume crosses the immediateFloor before the coalesce window elapses,
// the debouncer must flush synchronously so the sender's window opens
// without the 25 ms delay.
func TestGrantDebouncer_ImmediateFloorFlushesSynchronously(t *testing.T) {
	fw := &fakeWindow{grant: 1024}
	var updates atomic.Uint64
	sendUpdate := func(sid uint64, credit uint64) { updates.Add(1) }

	// Floor = 1000 bytes. First 3 records stay below; 4th crosses.
	d := newGrantDebouncer(fw, sendUpdate, 7, 1000)

	d.Record(300) // 300 pending
	d.Record(300) // 600 pending
	d.Record(300) // 900 pending
	// Still below floor — timer running, no flush.
	if calls, _ := fw.snapshot(); calls != 0 {
		t.Fatalf("below floor: unexpected flush calls=%d", calls)
	}

	d.Record(200) // 1100 pending ≥ 1000 → immediate flush
	if calls, total := fw.snapshot(); calls != 1 || total != 1100 {
		t.Errorf("above floor: expected 1 flush of 1100 bytes, got calls=%d total=%d", calls, total)
	}
	if u := updates.Load(); u != 1 {
		t.Errorf("above floor: wire updates got %d, want 1", u)
	}
}

// Close must flush remaining pending bytes so peers aren't left without
// credit for work the application already consumed.
func TestGrantDebouncer_CloseFlushesPending(t *testing.T) {
	fw := &fakeWindow{grant: 1}
	var updates atomic.Uint64
	sendUpdate := func(sid uint64, credit uint64) { updates.Add(1) }

	d := newGrantDebouncer(fw, sendUpdate, 11, 1<<20 /* high floor — never hit */)

	d.Record(512)
	d.Record(512)
	if calls, _ := fw.snapshot(); calls != 0 {
		t.Fatalf("pre-close: unexpected flush calls=%d", calls)
	}

	d.Close()
	if calls, total := fw.snapshot(); calls != 1 || total != 1024 {
		t.Errorf("close: expected final flush of 1024 bytes, got calls=%d total=%d", calls, total)
	}
	if u := updates.Load(); u != 1 {
		t.Errorf("close: wire updates got %d, want 1", u)
	}

	// Idempotent — second Close is a no-op; post-close Record is a no-op.
	d.Close()
	d.Record(256)
	if calls, total := fw.snapshot(); calls != 1 || total != 1024 {
		t.Errorf("post-close: state changed unexpectedly (calls=%d total=%d)", calls, total)
	}
}

// ReceiverConsume returning 0 (no trigger fired) must not emit a wire
// WINDOW_UPDATE. Only fires when the window's triggers say to emit.
func TestGrantDebouncer_ZeroGrantNoWireUpdate(t *testing.T) {
	fw := &fakeWindow{grant: 0} // all ReceiverConsume calls return 0
	var updates atomic.Uint64
	sendUpdate := func(sid uint64, credit uint64) { updates.Add(1) }

	d := newGrantDebouncer(fw, sendUpdate, 3, 0)
	d.Record(1024)
	time.Sleep(GrantCoalesceWindow + 50*time.Millisecond)

	if calls, _ := fw.snapshot(); calls != 1 {
		t.Errorf("expected 1 ReceiverConsume call (flush happened), got %d", calls)
	}
	if u := updates.Load(); u != 0 {
		t.Errorf("expected 0 wire updates (triggers didn't fire), got %d", u)
	}
}

// Real-window integration: a gossip-like pattern (4 MB initial, 70 KB
// payloads, 10 s gossip intervals) would stall because the three size-
// based triggers all have floors the gossip traffic doesn't hit. With
// the debouncer batching consume calls AND the TIMED trigger (see
// GrantMaxInterval), a grant fires within GrantMaxInterval regardless
// of pattern.
func TestGrantDebouncer_WithRealWindow_LargeWindowSmallPayload(t *testing.T) {
	const (
		bigWindow    = 4 * 1024 * 1024
		smallPayload = 70 * 1024
	)
	w := flow.NewStreamWindow(bigWindow)
	var updates atomic.Uint64
	var streamID uint64 = 0 // gossip
	sendUpdate := func(sid uint64, credit uint64) { updates.Add(1) }

	d := newGrantDebouncer(
		w,
		sendUpdate,
		streamID,
		int64(float64(bigWindow)*GrantImmediateFraction),
	)
	defer d.Close()

	// Feed a few small payloads — size-based triggers (THRESHOLD / EAGER
	// / WATERMARK) all require much more before firing.
	for i := 0; i < 3; i++ {
		d.Record(smallPayload)
	}
	// Coalesce window passes without a grant (no trigger fires yet).
	time.Sleep(GrantCoalesceWindow + 50*time.Millisecond)
	if u := updates.Load(); u != 0 {
		t.Fatalf("pre-TIMED: expected 0 updates, got %d", u)
	}

	// Wait past GrantMaxInterval (TIMED trigger threshold).
	time.Sleep(flow.GrantMaxInterval)

	// Next Record → flush → ReceiverConsume → TIMED trigger fires → grant → wire update.
	d.Record(smallPayload)
	time.Sleep(GrantCoalesceWindow + 50*time.Millisecond)

	if u := updates.Load(); u == 0 {
		t.Fatal("post-TIMED: expected at least 1 wire update from TIMED trigger")
	}
	if g := w.Stats().TimedGrants; g == 0 {
		t.Error("expected TimedGrants > 0")
	}
}
