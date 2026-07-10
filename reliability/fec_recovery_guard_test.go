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

// TestFECDecoder_RejectsRepairOnlyRecovery is the AE-M-13 regression: a
// repair-only group (Total==2, so dataCount==1) that has received ZERO real
// data frames must NOT fabricate a recovered DATA frame out of the repair
// payload alone. Pre-fix, tryRecover fell through both the `>= dataCount` and
// the `< dataCount-1` guards and returned the attacker-chosen repair bytes
// verbatim, which handleFECRepair -> deliverToStream then injected into a
// stream bypassing the per-stream anti-replay window and reorder buffer.
func TestFECDecoder_RejectsRepairOnlyRecovery(t *testing.T) {
	dec := NewFECDecoder()
	attacker := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	hdr := aether.FECHeader{GroupID: 7, Index: 1, Total: 2}

	if got := dec.AddRepair(hdr, attacker); got != nil {
		t.Fatalf("repair-only Total==2 group must not fabricate a recovered frame; got %x", got)
	}

	// Re-delivering the same repair (a replay attempt) must still not fabricate.
	if got := dec.AddRepair(hdr, attacker); got != nil {
		t.Fatalf("repeated repair-only delivery must not fabricate/replay a frame; got %x", got)
	}
}

// TestFECDecoder_RecoversLostDataShardFromShards is the AE-M-14 reliability-core
// regression: once the surviving DATA shards of a group are registered via
// AddData, a later FEC_REPAIR must reconstruct the single dropped shard. This
// is the decoder behavior the receiver-side feedFECData wiring
// (adapter/noise_dispatch.go, owned separately) depends on. With no AddData
// feed, every multi-frame group stayed repair-only and this recovery never
// fired. The AE-M-13 guard is a no-op here because len(received) == dataCount-1.
func TestFECDecoder_RecoversLostDataShardFromShards(t *testing.T) {
	enc := NewFECEncoder(4)
	dec := NewFECDecoder()

	payloads := [][]byte{
		{0x11, 0x22, 0x33, 0x44},
		{0x55, 0x66, 0x77, 0x88},
		{0x99, 0xAA, 0xBB, 0xCC},
		{0xDD, 0xEE, 0xFF, 0x01},
	}

	var repair *aether.Frame
	for _, p := range payloads {
		repair = enc.Add(p)
	}
	if repair == nil {
		t.Fatal("expected repair frame after 4th data")
	}

	// Register 3 of the 4 surviving DATA shards; drop index 2. Group total is 5
	// (4 data + 1 repair). Each AddData runs tryRecover but bails (no repair yet).
	dec.AddData(0, 0, 5, payloads[0])
	dec.AddData(0, 1, 5, payloads[1])
	dec.AddData(0, 3, 5, payloads[3])

	fecHdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	repairData := repair.Payload[aether.FECHeaderSize:]
	recovered := dec.AddRepair(fecHdr, repairData)

	if recovered == nil {
		t.Fatal("expected recovery of dropped shard (index 2) from surviving shards + repair")
	}
	if !bytes.Equal(recovered, payloads[2]) {
		t.Errorf("recovered shard: got %x, want %x", recovered, payloads[2])
	}

	// The recovered group self-deletes in tryRecover; it is NOT a Prune eviction.
	if ev := dec.EvictedCount(); ev != 0 {
		t.Errorf("recovered group should self-delete, not be evicted; EvictedCount=%d", ev)
	}
}
