/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package aether

import "testing"

// b1statsFrame builds a TypeSTATS frame with a payload of exactly n bytes and
// the given flags. TypeSTATS is used because it is the only minPayloadSizes
// entry whose size (StatsPayloadSize = 74) exceeds the 64-byte compression gate,
// so it is the only type that can reach Validate() still deflated.
func b1statsFrame(n int, flags FrameFlags) *Frame {
	return &Frame{
		Type:    TypeSTATS,
		Flags:   flags,
		Length:  uint32(n),
		Payload: make([]byte, n),
	}
}

// TestB1_MinPayloadSize_DeferredWhileCompressed is the B1 FIX.
//
// minPayloadSizes describes the UNCOMPRESSED wire size. writeFrame deflates any
// payload over 64 bytes, and StatsPayloadSize is 74, so every STATS frame goes
// out compressed — arriving at ~40 bytes, legitimately below its own minimum.
// Applying the minimum to the still-deflated length rejected healthy traffic as
// malformed once every 5 seconds per session (latent since StatsPayloadSize grew
// 34 -> 74 and crossed the 64-byte gate).
//
// The check must be DEFERRED while FlagCOMPRESSED is set — never dropped. The
// companion test below pins the "never dropped" half.
func TestB1_MinPayloadSize_DeferredWhileCompressed(t *testing.T) {
	// A deflated STATS payload: under the 74-byte minimum, flag set.
	compressed := b1statsFrame(40, FlagCOMPRESSED)
	if err := compressed.Validate(); err != nil {
		t.Errorf("B1 REGRESSION: a still-compressed STATS frame was rejected as "+
			"malformed (%v). The per-type minimum describes the UNCOMPRESSED size "+
			"and must not be applied before decompression — this is the defect that "+
			"produced a malformed-frame report every 5s per session", err)
	}

	// Control: a full-size STATS frame is valid either way.
	if err := b1statsFrame(int(StatsPayloadSize), 0).Validate(); err != nil {
		t.Errorf("a full-size uncompressed STATS frame must validate: %v", err)
	}
	if err := b1statsFrame(int(StatsPayloadSize), FlagCOMPRESSED).Validate(); err != nil {
		t.Errorf("a full-size compressed STATS frame must validate: %v", err)
	}
}

// TestB1_MinPayloadSize_StillEnforced_WhenNotCompressed is the CAPABILITY GUARD.
//
// The TypeSTATS entry in minPayloadSizes is deliberate anti-abuse machinery: its
// comment states it exists so an undersized STATS payload trips the abuse path
// instead of being silently dropped by the handler. The B1 fix must MOVE that
// check past decompression, NOT skip it — a naive "if compressed, bypass" would
// stop the false positives AND silently disarm a real guard, with every other
// test still green.
//
// Two cases cover both ways an undersized frame reaches Validate():
//   - never compressed (no flag) — the ordinary path, unchanged;
//   - post-decompression, where adapter/noise_dispatch.go clears FlagCOMPRESSED,
//     sets Length to the inflated size and re-runs Validate(). A frame that is
//     STILL short there is genuinely undersized and must be rejected.
func TestB1_MinPayloadSize_StillEnforced_WhenNotCompressed(t *testing.T) {
	// Case 1: undersized and never compressed — must still be rejected.
	if err := b1statsFrame(40, 0).Validate(); err == nil {
		t.Error("CAPABILITY LOST: an undersized UNCOMPRESSED STATS frame validated. " +
			"The minPayloadSizes TypeSTATS entry exists so undersized payloads reach " +
			"the abuse path rather than being silently dropped — it must stay enforced " +
			"for every frame that is not awaiting decompression")
	}

	// Case 2: the exact state the receive path re-validates in — flag cleared by
	// the decompress block, Length set to the inflated size, still under minimum.
	// This is where the deferred check must actually fire.
	postInflate := b1statsFrame(40, FlagCOMPRESSED)
	postInflate.Flags = postInflate.Flags.Clear(FlagCOMPRESSED) // as the adapter does
	if err := postInflate.Validate(); err == nil {
		t.Error("CAPABILITY LOST: a frame in the POST-DECOMPRESSION state (flag " +
			"cleared, length still below minimum) validated. The deferred minimum " +
			"must fire here — this is the only place it can, and adapter/" +
			"noise_dispatch.go re-runs Validate() immediately after inflating " +
			"precisely so it does")
	}

	// And the deferral is scoped to the minimum alone: the other structural
	// invariants must still hold for a compressed frame.
	mismatched := b1statsFrame(40, FlagCOMPRESSED)
	mismatched.Length = 41 // header disagrees with the payload
	if err := mismatched.Validate(); err == nil {
		t.Error("the FlagCOMPRESSED deferral must apply ONLY to the per-type minimum; " +
			"the payload/length mismatch check must still reject this frame")
	}
}
