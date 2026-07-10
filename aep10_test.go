/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package aether

import "testing"

// AE-P-10 regression: CongestionThrottle.Apply must clamp a peer-controlled
// severity (physically 0-255 on the wire) UP to 100, so RateFactor never
// returns a value outside its documented [0,1] range and ShouldStall stays
// correct. Symbols are AE-P-10-prefixed to avoid collisions in package aether.

// TestAEP10_ApplyClampsOversizedSeverity verifies an out-of-range severity is
// pinned to 100 (full congestion) rather than trusted verbatim.
func TestAEP10_ApplyClampsOversizedSeverity(t *testing.T) {
	var throttle CongestionThrottle
	throttle.Apply(CongestionPayload{Severity: 255, BackoffMs: 100})

	if got := throttle.Snapshot().Severity; got != 100 {
		t.Fatalf("Snapshot().Severity = %d, want 100 (clamped)", got)
	}
	if rf := throttle.RateFactor(); rf != 0.0 {
		t.Fatalf("RateFactor() = %v, want 0.0 for clamped severity", rf)
	}
	if !throttle.ShouldStall() {
		t.Fatalf("ShouldStall() = false, want true for severity 100")
	}
}

// TestAEP10_RateFactorAlwaysInRange is a property test over the full physical
// severity range: RateFactor must stay within [0,1] for every possible wire
// byte. Pre-fix this failed for severity > 100 (negative multiplier).
func TestAEP10_RateFactorAlwaysInRange(t *testing.T) {
	for s := 0; s <= 255; s++ {
		var throttle CongestionThrottle
		throttle.Apply(CongestionPayload{Severity: uint8(s), BackoffMs: 100})
		rf := throttle.RateFactor()
		if rf < 0.0 || rf > 1.0 {
			t.Fatalf("RateFactor() = %v for severity %d, want within [0,1]", rf, s)
		}
	}
}

// TestAEP10_WirePathClamp exercises the full Decode->Apply path a crafted peer
// frame takes: a 0xFF severity byte must not produce an out-of-range RateFactor.
func TestAEP10_WirePathClamp(t *testing.T) {
	p := DecodeCongestion([]byte{byte(CongestionQueueFull), 0xFF, 0x00, 0x64, 0x00})
	var throttle CongestionThrottle
	throttle.Apply(p)
	if rf := throttle.RateFactor(); rf < 0.0 || rf > 1.0 {
		t.Fatalf("RateFactor() = %v after wire-path apply, want within [0,1]", rf)
	}
}

// TestAEP10_InRangeSeverityUnchanged confirms valid in-range severities behave
// identically to before the clamp (no capability regression).
func TestAEP10_InRangeSeverityUnchanged(t *testing.T) {
	var throttle CongestionThrottle
	throttle.Apply(CongestionPayload{Severity: 50, BackoffMs: 100})

	if rf := throttle.RateFactor(); rf != 0.5 {
		t.Fatalf("RateFactor() = %v for severity 50, want 0.5", rf)
	}
	if got := throttle.Snapshot().Severity; got != 50 {
		t.Fatalf("Snapshot().Severity = %d, want 50 (unchanged)", got)
	}
}
