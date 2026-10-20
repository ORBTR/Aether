//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package adapter

import (
	"bytes"
	"errors"
	"testing"
)

// TestSplitMessageRejectsOversizedPayload: a payload that
// would need more than MaxFragments fragments must be rejected with
// ErrPayloadTooLarge rather than silently truncated to its first MaxFragments
// fragments. It also pins the boundary (exactly MaxFragments fragments must
// still succeed and round-trip losslessly) so an off-by-one can't wrongly
// reject the largest legal message or drop a byte.
func TestSplitMessageRejectsOversizedPayload(t *testing.T) {
	const maxPayload = 1200
	chunkSize := maxPayload - FragmentEnvelopeSize

	// 1) Oversize path: one byte past the MaxFragments ceiling must error
	//    with ErrPayloadTooLarge and return no fragments (no truncation).
	oversize := make([]byte, MaxFragments*chunkSize+1)
	frags, err := SplitMessage(fxBinding(), 1, oversize, maxPayload)
	if err == nil {
		t.Fatalf("oversize payload: expected error, got nil (frags=%d)", len(frags))
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize payload: expected ErrPayloadTooLarge, got %v", err)
	}
	if frags != nil {
		t.Fatalf("oversize payload: expected nil fragments, got %d", len(frags))
	}

	// 2) Boundary/no-regression: exactly MaxFragments fragments must succeed
	//    with a nil error and round-trip byte-for-byte through reassembly.
	boundary := make([]byte, MaxFragments*chunkSize)
	for i := range boundary {
		boundary[i] = byte(i * 31) // deterministic non-trivial content
	}
	frags, err = SplitMessage(fxBinding(), 1, boundary, maxPayload)
	if err != nil {
		t.Fatalf("boundary payload: unexpected error: %v", err)
	}
	if len(frags) != MaxFragments {
		t.Fatalf("boundary payload: expected %d fragments, got %d", MaxFragments, len(frags))
	}

	fb := NewFragmentBuffer()
	r := fxReceiver()
	var assembled []byte
	for i, frag := range frags {
		out, _, aerr := fb.Add(r, 7, frag)
		if aerr != nil {
			t.Fatalf("boundary reassembly: Add(frag %d) error: %v", i, aerr)
		}
		if i < len(frags)-1 {
			if out != nil {
				t.Fatalf("boundary reassembly: Add(frag %d) returned payload before final fragment", i)
			}
			continue
		}
		assembled = out
	}
	if !bytes.Equal(assembled, boundary) {
		t.Fatalf("boundary reassembly: round-trip mismatch (got %d bytes, want %d)",
			len(assembled), len(boundary))
	}

	// 3) Small payload: fits in a single frame → (nil, nil), no fragmentation.
	small := make([]byte, 100)
	frags, err = SplitMessage(fxBinding(), 1, small, maxPayload)
	if err != nil {
		t.Fatalf("small payload: unexpected error: %v", err)
	}
	if frags != nil {
		t.Fatalf("small payload: expected nil fragments, got %d", len(frags))
	}
}
