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

func TestFECEncoder_GroupComplete(t *testing.T) {
	enc := NewFECEncoder(4)

	// First 3 frames: no repair yet
	for i := 0; i < 3; i++ {
		f := enc.Add([]byte{byte(i), byte(i + 10), byte(i + 20)})
		if f != nil {
			t.Fatalf("frame %d: expected nil, got repair frame", i)
		}
	}

	// 4th frame: should trigger repair
	repair := enc.Add([]byte{3, 13, 23})
	if repair == nil {
		t.Fatal("4th frame should trigger FEC repair")
	}
	if repair.Type != aether.TypeFEC_REPAIR {
		t.Errorf("repair type: got %s, want FEC_REPAIR", repair.Type)
	}
}

func TestFECEncoder_Flush(t *testing.T) {
	enc := NewFECEncoder(4)

	enc.Add([]byte{0xAA})
	enc.Add([]byte{0xBB})

	repair := enc.Flush()
	if repair == nil {
		t.Fatal("Flush should produce a repair frame")
	}
	if repair.Type != aether.TypeFEC_REPAIR {
		t.Errorf("repair type: got %s, want FEC_REPAIR", repair.Type)
	}
}

func TestFECEncoder_FlushEmpty(t *testing.T) {
	enc := NewFECEncoder(4)
	if enc.Flush() != nil {
		t.Error("Flush on empty encoder should return nil")
	}
}

func TestFECRoundTrip_NoLoss(t *testing.T) {
	enc := NewFECEncoder(3)
	dec := NewFECDecoder()

	payloads := [][]byte{
		{0x10, 0x20, 0x30},
		{0x40, 0x50, 0x60},
		{0x70, 0x80, 0x90},
	}

	var repair *aether.Frame
	for i, p := range payloads {
		repair = enc.Add(p)
		// Record in decoder
		dec.AddData(0, uint8(i), 4, p) // 4 = 3 data + 1 repair
	}

	if repair == nil {
		t.Fatal("expected repair frame after 3rd data")
	}

	// Add repair — all data present, should return nil (no recovery needed)
	fecHdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	repairData := repair.Payload[aether.FECHeaderSize:]
	recovered := dec.AddRepair(fecHdr, repairData)
	if recovered != nil {
		t.Error("no frames lost — should not recover anything")
	}
}

func TestFECRoundTrip_SingleLoss(t *testing.T) {
	enc := NewFECEncoder(3)
	dec := NewFECDecoder()

	payloads := [][]byte{
		{0x10, 0x20, 0x30},
		{0x40, 0x50, 0x60},
		{0x70, 0x80, 0x90},
	}

	var repair *aether.Frame
	for _, p := range payloads {
		repair = enc.Add(p)
	}
	if repair == nil {
		t.Fatal("expected repair frame")
	}

	// Simulate: frame 1 (index 1) lost, frames 0 and 2 received
	dec.AddData(0, 0, 4, payloads[0])
	dec.AddData(0, 2, 4, payloads[2])

	// Add repair — should recover frame 1
	fecHdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	repairData := repair.Payload[aether.FECHeaderSize:]
	recovered := dec.AddRepair(fecHdr, repairData)

	if recovered == nil {
		t.Fatal("expected recovery of lost frame")
	}
	if !bytes.Equal(recovered, payloads[1]) {
		t.Errorf("recovered: got %x, want %x", recovered, payloads[1])
	}
}

func TestFECRoundTrip_TwoLost(t *testing.T) {
	enc := NewFECEncoder(3)
	dec := NewFECDecoder()

	payloads := [][]byte{
		{0x10, 0x20},
		{0x30, 0x40},
		{0x50, 0x60},
	}

	var repair *aether.Frame
	for _, p := range payloads {
		repair = enc.Add(p)
	}

	// Only frame 0 received — two lost — can't recover
	dec.AddData(0, 0, 4, payloads[0])
	fecHdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	repairData := repair.Payload[aether.FECHeaderSize:]
	recovered := dec.AddRepair(fecHdr, repairData)

	if recovered != nil {
		t.Error("two frames lost — should not recover")
	}
}

func TestFECRoundTrip_VariableLengthPayloads(t *testing.T) {
	enc := NewFECEncoder(3)
	dec := NewFECDecoder()

	// Different length payloads — shorter ones are zero-padded for XOR
	payloads := [][]byte{
		{0xAA, 0xBB, 0xCC, 0xDD},
		{0x11, 0x22},
		{0x33, 0x44, 0x55},
	}

	var repair *aether.Frame
	for _, p := range payloads {
		repair = enc.Add(p)
	}

	// Lose frame 0, keep frames 1 and 2
	dec.AddData(0, 1, 4, payloads[1])
	dec.AddData(0, 2, 4, payloads[2])

	fecHdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	repairData := repair.Payload[aether.FECHeaderSize:]
	recovered := dec.AddRepair(fecHdr, repairData)

	if recovered == nil {
		t.Fatal("expected recovery")
	}
	// Recovered should match original (zero-padded to max length)
	for i := 0; i < len(payloads[0]); i++ {
		if recovered[i] != payloads[0][i] {
			t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, recovered[i], payloads[0][i])
		}
	}
}

func TestFECDecoder_Prune(t *testing.T) {
	dec := NewFECDecoder()

	// Create 10 incomplete groups
	for i := uint32(0); i < 10; i++ {
		dec.AddData(i, 0, 4, []byte{byte(i)})
	}

	dec.Prune(5)

	// Should have at most 5 groups remaining
	dec.mu.Lock()
	count := len(dec.groups)
	dec.mu.Unlock()

	if count > 5 {
		t.Errorf("after Prune(5): got %d groups, want <= 5", count)
	}
}

func TestFECEncoder_MultipleGroups(t *testing.T) {
	enc := NewFECEncoder(2)

	// Group 1
	if enc.Add([]byte{0x01}) != nil {
		t.Error("first frame shouldn't trigger repair")
	}
	repair1 := enc.Add([]byte{0x02})
	if repair1 == nil {
		t.Fatal("second frame should trigger repair")
	}

	// Group 2
	if enc.Add([]byte{0x03}) != nil {
		t.Error("third frame shouldn't trigger repair")
	}
	repair2 := enc.Add([]byte{0x04})
	if repair2 == nil {
		t.Fatal("fourth frame should trigger repair")
	}

	// Different group IDs
	hdr1 := aether.DecodeFECHeader(repair1.Payload[:aether.FECHeaderSize])
	hdr2 := aether.DecodeFECHeader(repair2.Payload[:aether.FECHeaderSize])
	if hdr1.GroupID == hdr2.GroupID {
		t.Error("different groups should have different GroupIDs")
	}
}
