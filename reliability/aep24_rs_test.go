/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

// AE-P-24 regression tests for reliability/fec_rs.go (RSDecoder). These cover:
//   - validate-before-allocate (malformed Total/Index never inserts a group)
//   - the inline insert-time group budget (SetMaxGroups) bounding a flood of
//     unique GroupIDs between periodic Prune sweeps
//   - default-off behaviour (no cap wired => no inline eviction)
//   - happy-path RS recovery still completes when the inline cap is active.
//
// All helpers/funcs are AE-P-24-prefixed to avoid cross-agent symbol collisions
// in the shared `reliability` package.

// aep24RSPayload builds a well-formed AddRepair payload: [shardLen:2 BE][shard].
func aep24RSPayload(shardLen int) []byte {
	p := make([]byte, 2+shardLen)
	p[0] = byte(shardLen >> 8)
	p[1] = byte(shardLen)
	return p
}

// aep24RSGroupCount reads len(d.groups) under the decoder lock (white-box).
func aep24RSGroupCount(d *RSDecoder) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.groups)
}

// TestAEP24_RSAddRepairMalformedNoAlloc: a malformed repair (Total==0, or Index
// outside its own Total) must be rejected BEFORE any group is allocated in
// d.groups keyed by the peer-controlled GroupID.
func TestAEP24_RSAddRepairMalformedNoAlloc(t *testing.T) {
	dec, err := NewRSDecoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}

	// Total==0: no data shard could ever exist for this group.
	dec.AddRepair(aether.FECHeader{GroupID: 5, Index: 0, Total: 0}, aep24RSPayload(4))
	if n := aep24RSGroupCount(dec); n != 0 {
		t.Fatalf("Total==0 repair allocated a group: len(groups)=%d, want 0", n)
	}

	// Index >= Total: a frame claiming an index outside its own group size.
	dec.AddRepair(aether.FECHeader{GroupID: 6, Index: 200, Total: 8}, aep24RSPayload(4))
	if n := aep24RSGroupCount(dec); n != 0 {
		t.Fatalf("out-of-range Index repair allocated a group: len(groups)=%d, want 0", n)
	}

	// Index == Total (boundary): still out of range, must be rejected.
	dec.AddRepair(aether.FECHeader{GroupID: 7, Index: 10, Total: 10}, aep24RSPayload(4))
	if n := aep24RSGroupCount(dec); n != 0 {
		t.Fatalf("Index==Total repair allocated a group: len(groups)=%d, want 0", n)
	}
}

// TestAEP24_RSInlineCapBoundsGroups: with SetMaxGroups(cap) a sub-second flood
// of unique-GroupID repairs (each well-formed and retained) cannot grow the map
// beyond the configured cap, and eviction is observed. No Prune calls are made.
func TestAEP24_RSInlineCapBoundsGroups(t *testing.T) {
	dec, err := NewRSDecoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}
	const capN = 128
	dec.SetMaxGroups(capN)

	for i := uint32(1); i <= 2000; i++ {
		// Well-formed repair: Index 9 < Total 10, retained (received 1 < k=8).
		dec.AddRepair(aether.FECHeader{GroupID: i, Index: 9, Total: 10}, aep24RSPayload(8))
		if got := aep24RSGroupCount(dec); got > capN {
			t.Fatalf("group count exceeded inline cap during flood: got %d at i=%d, cap=%d", got, i, capN)
		}
	}
	if got := aep24RSGroupCount(dec); got > capN {
		t.Fatalf("final group count %d exceeds cap %d", got, capN)
	}
	if dec.EvictedCount() == 0 {
		t.Fatal("expected inline evictions during a unique-GroupID flood, got 0")
	}
}

// TestAEP24_RSInlineCapDisabledByDefault: without SetMaxGroups the inline cap is
// disabled (maxGroups==0), preserving existing behaviour — the map grows freely
// and no inline eviction occurs.
func TestAEP24_RSInlineCapDisabledByDefault(t *testing.T) {
	dec, err := NewRSDecoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}
	const n = 300 // well past DefaultMaxFECGroups (256)
	for i := uint32(1); i <= n; i++ {
		dec.AddRepair(aether.FECHeader{GroupID: i, Index: 9, Total: 10}, aep24RSPayload(8))
	}
	if got := aep24RSGroupCount(dec); got != n {
		t.Fatalf("cap disabled: expected %d groups, got %d", n, got)
	}
	if ev := dec.EvictedCount(); ev != 0 {
		t.Fatalf("cap disabled: expected 0 inline evictions, got %d", ev)
	}
}

// TestAEP24_RSRecoveryPreservedWithCap: with the inline cap active, a flood of
// low-ID unique-GroupID repairs must not evict a legitimate high-ID group that
// is mid-recovery — evictOldestLocked drops the lowest ID, so the highest-ID
// legit group survives and still reconstructs.
func TestAEP24_RSRecoveryPreservedWithCap(t *testing.T) {
	enc, err := NewRSEncoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSEncoder: %v", err)
	}
	dec, err := NewRSDecoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}
	dec.SetMaxGroups(4)

	originals := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		[]byte("charlie-1"),
		[]byte("delta-payload-larger"),
		[]byte("echo"),
		[]byte("foxtrot-abc"),
		[]byte("golf-x"),
		[]byte("hotel-y-z"),
	}
	var repairs []*aether.Frame
	for _, p := range originals {
		if out := enc.Add(p); out != nil {
			repairs = out
		}
	}
	if len(repairs) != 2 {
		t.Fatalf("expected 2 parity frames, got %d", len(repairs))
	}

	// legitGID is the highest ID, so evictOldestLocked (lowest-ID first) never
	// targets it while lower-ID flood groups are present.
	const legitGID = uint32(1_000_000)

	// Deliver 6 of 8 data shards for the legit group (drop 2, 4).
	deliveredIdx := []int{0, 1, 3, 5, 6, 7}
	for _, i := range deliveredIdx {
		dec.AddData(legitGID, uint8(i), 10, originals[i])
	}

	// Flood many low-ID unique repair-only groups to force inline eviction.
	for i := uint32(0); i < 200; i++ {
		dec.AddRepair(aether.FECHeader{GroupID: i, Index: 9, Total: 10}, aep24RSPayload(8))
	}
	if dec.EvictedCount() == 0 {
		t.Fatal("expected inline evictions from the low-ID flood")
	}

	// Feed the legit group's parity frames — recovery must still complete.
	var recovered [][]byte
	for _, r := range repairs {
		hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
		hdr.GroupID = legitGID
		if out := dec.AddRepair(hdr, r.Payload[aether.FECHeaderSize:]); out != nil {
			recovered = out
		}
	}
	if recovered == nil {
		t.Fatal("legit high-ID group failed to recover under the inline cap")
	}
	if len(recovered) != 8 {
		t.Fatalf("recovered %d shards, want 8", len(recovered))
	}
	for i, orig := range originals {
		if !bytes.HasPrefix(recovered[i], orig) {
			t.Errorf("shard %d: got %q, want prefix %q", i, recovered[i], orig)
		}
	}
}
