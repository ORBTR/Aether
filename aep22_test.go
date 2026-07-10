package aether

import (
	"strings"
	"testing"
)

// AE-P-22 regression: the STATS frame wire size is 74 bytes (StatsPayloadSize),
// not the stale 34 bytes the protocol-spec doc used to claim. frame.go's
// minPayloadSizes gate rejects any STATS frame shorter than StatsPayloadSize at
// Validate() so the abuse path fires instead of a handler silently dropping.
// These tests lock in that behaviour so nobody "reconciles" AE-P-22 by relaxing
// the gate (which would lower the undersized-frame abuse limit) instead of
// correcting the documentation. See docs/protocol-spec.md §2.7 / §27.

// aep22StatsFrame builds a STATS frame carrying a payload of exactly n bytes
// with a matching Length header (so the only Validate failure under test is the
// per-type minimum-size gate, never the length/actual mismatch check).
func aep22StatsFrame(n uint32) *Frame {
	return &Frame{
		Type:    TypeSTATS,
		Length:  n,
		Payload: make([]byte, n),
	}
}

// TestAEP22_StatsPayloadSizeIsSeventyFour pins the constant the doc now
// documents; a future encoder/layout change that drifts this off 74 must
// update docs/protocol-spec.md in lockstep.
func TestAEP22_StatsPayloadSizeIsSeventyFour(t *testing.T) {
	if StatsPayloadSize != 74 {
		t.Fatalf("AE-P-22: StatsPayloadSize = %d, want 74 (wire spec + EncodeStats layout)", StatsPayloadSize)
	}
}

// TestAEP22_ValidateRejectsUndersizedStats confirms the minPayloadSizes gate
// rejects a STATS frame carrying the stale 34-byte payload the old doc
// described, as well as the just-below-boundary case.
func TestAEP22_ValidateRejectsUndersizedStats(t *testing.T) {
	for _, n := range []uint32{0, 34, StatsPayloadSize - 1} {
		err := aep22StatsFrame(n).Validate()
		if err == nil {
			t.Fatalf("AE-P-22: Validate() accepted undersized STATS payload (%d bytes); want rejection", n)
		}
		if !strings.Contains(err.Error(), "payload too small") {
			t.Fatalf("AE-P-22: Validate() for %d-byte STATS returned %q; want a \"payload too small\" error", n, err)
		}
	}
}

// TestAEP22_ValidateAcceptsFullStats confirms a spec-conformant 74-byte STATS
// frame passes Validate() — the exact size the corrected doc now advertises.
func TestAEP22_ValidateAcceptsFullStats(t *testing.T) {
	if err := aep22StatsFrame(StatsPayloadSize).Validate(); err != nil {
		t.Fatalf("AE-P-22: Validate() rejected a full %d-byte STATS frame: %v", StatsPayloadSize, err)
	}
}
