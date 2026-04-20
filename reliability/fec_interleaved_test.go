/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

// TestInterleavedFEC_EncoderRepairEmission verifies that an InterleavedFECEncoder
// emits repair frames only after each sub-group (A / B) has filled to groupSize.
func TestInterleavedFEC_EncoderRepairEmission(t *testing.T) {
	const groupSize = 3
	enc := NewInterleavedFECEncoder(groupSize)

	// Feed 2*groupSize frames. Even-indexed → groupA, odd-indexed → groupB.
	// Each sub-group should emit exactly one repair frame once it fills.
	totalRepairs := 0
	for i := 0; i < 2*groupSize; i++ {
		repairs := enc.Add([]byte{byte(i), byte(i + 1), byte(i + 2)})
		totalRepairs += len(repairs)
	}

	if totalRepairs != 2 {
		t.Fatalf("expected 2 repair frames across 2 sub-groups, got %d", totalRepairs)
	}
}

// TestInterleavedFEC_EncoderMinimumGroupSize verifies that sub-size-2 coerces
// to a minimum group size of 2.
func TestInterleavedFEC_EncoderMinimumGroupSize(t *testing.T) {
	enc := NewInterleavedFECEncoder(1)
	// With coerced groupSize=2, two frames into sub-group A should fire a repair.
	// Feed 4 frames: indexes 0,2 into A; indexes 1,3 into B → 2 repairs total.
	total := 0
	for i := 0; i < 4; i++ {
		total += len(enc.Add([]byte{byte(i)}))
	}
	if total != 2 {
		t.Fatalf("expected 2 repairs with coerced groupSize=2, got %d", total)
	}
}

// TestInterleavedFEC_FlushPartialGroups verifies Flush forces repair emission
// for any partially-filled sub-group.
func TestInterleavedFEC_FlushPartialGroups(t *testing.T) {
	enc := NewInterleavedFECEncoder(4)

	// Feed 3 frames only — neither sub-group fills (A has 2, B has 1).
	for i := 0; i < 3; i++ {
		if r := enc.Add([]byte{byte(i)}); len(r) != 0 {
			t.Fatalf("frame %d: unexpected early repair", i)
		}
	}

	repairs := enc.Flush()
	if len(repairs) != 2 {
		t.Fatalf("expected 2 repairs from Flush (A + B partial), got %d", len(repairs))
	}

	// Second Flush must be a no-op — buffers are drained.
	if extra := enc.Flush(); len(extra) != 0 {
		t.Fatalf("expected 0 repairs from second Flush, got %d", len(extra))
	}
}

// TestInterleavedFEC_RoundTripWithinGroupLoss covers the single-frame-loss case
// inside a single sub-group — equivalent to BasicXOR recovery but routed via
// the interleaved decoder.
func TestInterleavedFEC_RoundTripWithinGroupLoss(t *testing.T) {
	const groupSize = 3
	enc := NewInterleavedFECEncoder(groupSize)
	dec := NewInterleavedFECDecoder()

	// 6 frames → 3 go to A (indexes 0,2,4), 3 go to B (indexes 1,3,5).
	payloads := [][]byte{
		{0x10, 0x11, 0x12},
		{0x20, 0x21, 0x22},
		{0x30, 0x31, 0x32},
		{0x40, 0x41, 0x42},
		{0x50, 0x51, 0x52},
		{0x60, 0x61, 0x62},
	}

	var repairs []*aether.Frame
	for _, p := range payloads {
		repairs = append(repairs, enc.Add(p)...)
	}
	if len(repairs) != 2 {
		t.Fatalf("expected 2 repair frames, got %d", len(repairs))
	}

	// Simulate: frame at index 2 (sub-group A, seqInGroup=1) is lost.
	// Deliver all other frames + both repairs.
	for i, p := range payloads {
		if i == 2 {
			continue
		}
		// groupID in each sub-decoder starts at 0. Since seqInGroup is the
		// position within the sub-group (not the global index), compute it.
		var seqInGroup uint8
		if i%2 == 0 {
			seqInGroup = uint8(i / 2)
		} else {
			seqInGroup = uint8(i / 2)
		}
		dec.AddData(i, 0, seqInGroup, uint8(groupSize+1), p)
	}

	var recovered []byte
	for _, r := range repairs {
		hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
		data := r.Payload[aether.FECHeaderSize:]
		if got := dec.AddRepair(hdr, data); got != nil {
			recovered = got
		}
	}

	if recovered == nil {
		t.Fatal("expected in-group recovery of lost frame 2")
	}
	// Lost payload was payloads[2] = {0x30, 0x31, 0x32}.
	// Since all sub-group payloads in this test are the same length, the recovered
	// bytes must match byte-for-byte.
	if !bytes.Equal(recovered, payloads[2]) {
		t.Fatalf("recovered mismatch: got %x, want %x", recovered, payloads[2])
	}
}

// TestInterleavedFEC_BurstLossAcrossGroups covers the signature benefit of
// interleaving: two consecutive frames are lost, one falls in A and one in B,
// so BOTH are recoverable (plain XOR would only recover one).
func TestInterleavedFEC_BurstLossAcrossGroups(t *testing.T) {
	const groupSize = 3
	enc := NewInterleavedFECEncoder(groupSize)
	dec := NewInterleavedFECDecoder()

	payloads := [][]byte{
		{0xA0, 0xA1},
		{0xB0, 0xB1},
		{0xC0, 0xC1},
		{0xD0, 0xD1},
		{0xE0, 0xE1},
		{0xF0, 0xF1},
	}

	var repairs []*aether.Frame
	for _, p := range payloads {
		repairs = append(repairs, enc.Add(p)...)
	}
	if len(repairs) != 2 {
		t.Fatalf("expected 2 repair frames, got %d", len(repairs))
	}

	// Burst loss: frames at global indexes 2 (A) and 3 (B) are both lost.
	lost := map[int]bool{2: true, 3: true}
	for i, p := range payloads {
		if lost[i] {
			continue
		}
		seqInGroup := uint8(i / 2)
		dec.AddData(i, 0, seqInGroup, uint8(groupSize+1), p)
	}

	recovered := map[int][]byte{}
	for _, r := range repairs {
		hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
		data := r.Payload[aether.FECHeaderSize:]
		// Each sub-decoder handles its own group. We call both — only the
		// matching one will recover.
		if got := dec.AddRepair(hdr, data); got != nil {
			// We don't know which lost index it corresponds to without more
			// metadata; record under whichever position matches.
			for idx := range lost {
				if bytes.Equal(got, payloads[idx]) {
					recovered[idx] = got
				}
			}
		}
	}

	if len(recovered) != 2 {
		t.Fatalf("expected both burst-lost frames recovered, got %d: %v", len(recovered), recovered)
	}
	for idx := range lost {
		if !bytes.Equal(recovered[idx], payloads[idx]) {
			t.Fatalf("burst recovery mismatch at %d: got %x, want %x", idx, recovered[idx], payloads[idx])
		}
	}
}

// TestInterleavedFEC_TooManyLossesFailGracefully — losing 2 frames that land in
// the SAME sub-group exceeds XOR recovery capacity. Must not panic, must not
// produce garbage; returns nil.
func TestInterleavedFEC_TooManyLossesFailGracefully(t *testing.T) {
	const groupSize = 3
	enc := NewInterleavedFECEncoder(groupSize)
	dec := NewInterleavedFECDecoder()

	payloads := [][]byte{
		{0x11}, {0x22}, {0x33}, {0x44}, {0x55}, {0x66},
	}
	var repairs []*aether.Frame
	for _, p := range payloads {
		repairs = append(repairs, enc.Add(p)...)
	}

	// Lose indexes 0 and 2 — BOTH in sub-group A. Sub-group B is intact.
	lost := map[int]bool{0: true, 2: true}
	for i, p := range payloads {
		if lost[i] {
			continue
		}
		seqInGroup := uint8(i / 2)
		dec.AddData(i, 0, seqInGroup, uint8(groupSize+1), p)
	}

	anyRecovered := false
	for _, r := range repairs {
		hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
		data := r.Payload[aether.FECHeaderSize:]
		if got := dec.AddRepair(hdr, data); got != nil {
			// Group A should fail (2 lost). Group B has no losses → nil.
			// If anything comes back, it indicates the B decoder recovered
			// nothing (correct) or A produced garbage (BUG).
			for idx := range lost {
				if bytes.Equal(got, payloads[idx]) {
					anyRecovered = true
				}
			}
		}
	}
	if anyRecovered {
		t.Fatal("sub-group A had 2 losses; interleaved XOR must not recover either")
	}
}

// TestInterleavedFEC_PruneBoundsMemory ensures Prune on the interleaved decoder
// limits group state in both sub-decoders.
func TestInterleavedFEC_PruneBoundsMemory(t *testing.T) {
	dec := NewInterleavedFECDecoder()

	// Stuff lots of per-group state into both sub-decoders.
	for i := 0; i < 20; i++ {
		dec.AddData(i, uint32(i), 0, 4, []byte{byte(i)})
	}

	dec.Prune(3)

	dec.mu.Lock()
	aCount := len(dec.groupA.groups)
	bCount := len(dec.groupB.groups)
	dec.mu.Unlock()

	if aCount > 3 || bCount > 3 {
		t.Fatalf("Prune(3) failed: groupA=%d groupB=%d", aCount, bCount)
	}
}

// TestInterleavedFEC_TableDrivenRecovery is a table-driven sweep across
// groupSize × loss patterns.
func TestInterleavedFEC_TableDrivenRecovery(t *testing.T) {
	cases := []struct {
		name        string
		groupSize   int
		nFrames     int
		lostIndexes []int
		recoverable bool
	}{
		{"no-loss groupSize=2", 2, 4, nil, true},
		{"single-loss-in-A groupSize=3", 3, 6, []int{0}, true},
		{"single-loss-in-B groupSize=3", 3, 6, []int{1}, true},
		{"burst-across-groups groupSize=3", 3, 6, []int{2, 3}, true},
		{"double-loss-same-group groupSize=3", 3, 6, []int{0, 2}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := NewInterleavedFECEncoder(tc.groupSize)
			dec := NewInterleavedFECDecoder()

			payloads := make([][]byte, tc.nFrames)
			for i := range payloads {
				payloads[i] = []byte{byte(i + 1), byte(i*2 + 1)}
			}

			var repairs []*aether.Frame
			for _, p := range payloads {
				repairs = append(repairs, enc.Add(p)...)
			}

			lost := map[int]bool{}
			for _, idx := range tc.lostIndexes {
				lost[idx] = true
			}

			for i, p := range payloads {
				if lost[i] {
					continue
				}
				dec.AddData(i, 0, uint8(i/2), uint8(tc.groupSize+1), p)
			}

			recovered := map[int][]byte{}
			for _, r := range repairs {
				hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
				data := r.Payload[aether.FECHeaderSize:]
				if got := dec.AddRepair(hdr, data); got != nil {
					for idx := range lost {
						if bytes.Equal(got, payloads[idx]) {
							recovered[idx] = got
						}
					}
				}
			}

			if tc.recoverable {
				if len(recovered) != len(tc.lostIndexes) {
					t.Fatalf("expected %d recoveries, got %d", len(tc.lostIndexes), len(recovered))
				}
			} else {
				// At least one loss must fail; verify we didn't claim everything.
				if len(recovered) == len(tc.lostIndexes) {
					t.Fatalf("expected graceful failure, got full recovery %v", recovered)
				}
			}
		})
	}
}
