/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"testing"
)

// TestAEL14_FrameType_IsValid_RejectsReservedHole is the AE-L-14 regression
// guard. Before the fix, FrameType.IsValid() range-checked
// [TypeDATA..TypeCONGESTION], which admitted the reserved hole at 0x09
// (between TypeACK=0x08 and TypePRIORITY=0x0A). A Type=0x09 frame passed
// Validate and was silently dropped at dispatch instead of being scored via
// reportAbuse(ReasonMalformedFrame). This test locks in that 0x09 now fails
// IsValid/Validate, that all defined types still validate, and that the
// out-of-range boundaries are unchanged.
func TestAEL14_FrameType_IsValid_RejectsReservedHole(t *testing.T) {
	// (1) The reserved in-range hole must now be rejected.
	if FrameType(0x09).IsValid() {
		t.Errorf("AE-L-14: FrameType(0x09) must be invalid (reserved hole between TypeACK and TypePRIORITY)")
	}

	// (2) The malformed-frame gate must fire: Validate rejects 0x09, which is
	// the exact behaviour reportAbuse(ReasonMalformedFrame) keys off.
	if err := (&Frame{Type: FrameType(0x09)}).Validate(); err == nil {
		t.Errorf("AE-L-14: (&Frame{Type: 0x09}).Validate() must return a non-nil error so the abuse path fires")
	}

	// (3) Capability regression guard — every defined type must still validate.
	ael14Defined := []FrameType{
		TypeDATA, TypeOPEN, TypeCLOSE, TypeRESET, TypeWINDOW, TypePING,
		TypePONG, TypeACK, TypePRIORITY, TypeGOAWAY, TypeFEC_REPAIR,
		TypeWHOIS, TypeRENDEZVOUS, TypeNETWORK_CONFIG, TypeHANDSHAKE,
		TypeSTATS, TypeTRACE, TypePATH_PROBE, TypeCONGESTION,
	}
	for _, ft := range ael14Defined {
		if !ft.IsValid() {
			t.Errorf("AE-L-14: defined type %s (0x%02X) must remain valid", ft, byte(ft))
		}
	}

	// (4) Out-of-range boundaries unchanged: below TypeDATA and above
	// TypeCONGESTION both stay invalid.
	if FrameType(0x00).IsValid() {
		t.Errorf("AE-L-14: FrameType(0x00) must be invalid")
	}
	if FrameType(0x15).IsValid() {
		t.Errorf("AE-L-14: FrameType(0x15) must be invalid")
	}
}
