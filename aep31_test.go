/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * AE-P-31 regression tests: short-header DATA decoders must not commit a
 * full declared-size heap allocation before the peer has proven it is
 * delivering the body. A tiny header declaring up to MaxPayloadSize (16 MB)
 * with no body must fail cheaply, while legitimate large payloads still
 * decode in full (no capability loss).
 */
package aether

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
)

// aep31payload builds a length-sz payload with a position-dependent pattern so
// that any corruption across the maxShortPayloadPrealloc copy boundary is caught.
func aep31payload(sz uint32) []byte {
	b := make([]byte, sz)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

// aep31shortHeader builds the 8-byte DecodeDataShort header (indicator already
// consumed): streamID:2, seqDelta:2, length:4.
func aep31shortHeader(streamID uint16, seqDelta uint16, length uint32) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], streamID)
	binary.BigEndian.PutUint16(h[2:4], seqDelta)
	binary.BigEndian.PutUint32(h[4:8], length)
	return h
}

// aep31allocDelta returns the number of bytes allocated on the heap during fn.
// TotalAlloc is cumulative and never decreases, so the delta is the bytes
// allocated by fn regardless of subsequent GC.
func aep31allocDelta(fn func()) uint64 {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	fn()
	runtime.ReadMemStats(&m1)
	return m1.TotalAlloc - m0.TotalAlloc
}

// AE-P-31: a tiny short-header DATA frame declaring ~16 MB with NO body must
// return an error and must NOT allocate anywhere near the declared size.
func TestAEP31_DecodeDataShort_NoBody_BoundedAlloc(t *testing.T) {
	const declared = uint32(0x00FFFFFF) // 16 MB - 1
	hdr := aep31shortHeader(0, 0, declared)

	c := NewCompressor()
	var err error
	delta := aep31allocDelta(func() {
		_, err = c.DecodeDataShort(bytes.NewReader(hdr))
	})
	if err == nil {
		t.Fatalf("DecodeDataShort: expected error for header declaring %d bytes with no body", declared)
	}
	// Pre-fix this allocated the full ~16 MB up-front; post-fix at most one
	// maxShortPayloadPrealloc (64 KB) chunk plus small bookkeeping.
	if delta > 1<<20 {
		t.Errorf("allocation %d bytes exceeds 1 MB bound (declared %d, prealloc cap %d) — full-size prealloc regression",
			delta, declared, maxShortPayloadPrealloc)
	}
}

// AE-P-31: same defence for the varint short-header DATA decoder.
func TestAEP31_DecodeDataShortVar_NoBody_BoundedAlloc(t *testing.T) {
	const declared = uint32(0x00FFFFFF)
	var b bytes.Buffer
	b.Write(make([]byte, 4)) // streamID:2 + seqDelta:2 (zeros)
	if _, err := EncodeVarLength(&b, declared); err != nil {
		t.Fatalf("EncodeVarLength: %v", err)
	}
	// No body follows.

	c := NewCompressor()
	var err error
	delta := aep31allocDelta(func() {
		_, err = c.DecodeDataShortVar(bytes.NewReader(b.Bytes()))
	})
	if err == nil {
		t.Fatalf("DecodeDataShortVar: expected error for header declaring %d bytes with no body", declared)
	}
	if delta > 1<<20 {
		t.Errorf("allocation %d bytes exceeds 1 MB bound (declared %d) — full-size prealloc regression", delta, declared)
	}
}

// AE-P-31: capability preserved — payloads across the prealloc boundary, up to
// well past it, still round-trip byte-for-byte through both short decoders.
func TestAEP31_RoundTrip_CapabilityPreserved(t *testing.T) {
	sizes := []uint32{
		0,
		1,
		maxShortPayloadPrealloc - 1,
		maxShortPayloadPrealloc,
		maxShortPayloadPrealloc + 1,
		1 << 20,
	}
	for _, sz := range sizes {
		payload := aep31payload(sz)

		// Fixed-width uint32 short header (0x82).
		encShort := NewCompressor()
		var bufShort bytes.Buffer
		fShort := &Frame{StreamID: 7, Type: TypeDATA, SeqNo: 0, Length: sz, Payload: payload}
		if _, err := encShort.EncodeDataShort(&bufShort, fShort); err != nil {
			t.Fatalf("EncodeDataShort(sz=%d): %v", sz, err)
		}
		decShort := NewCompressor()
		gotShort, err := decShort.DecodeDataShort(bytes.NewReader(bufShort.Bytes()[1:])) // strip indicator
		if err != nil {
			t.Fatalf("DecodeDataShort(sz=%d): %v", sz, err)
		}
		if gotShort.Length != sz {
			t.Errorf("DecodeDataShort(sz=%d): Length=%d", sz, gotShort.Length)
		}
		if !bytes.Equal(gotShort.Payload, payload) {
			t.Errorf("DecodeDataShort(sz=%d): payload mismatch", sz)
		}

		// Varint short header (0x86).
		encVar := NewCompressor()
		var bufVar bytes.Buffer
		fVar := &Frame{StreamID: 7, Type: TypeDATA, SeqNo: 0, Length: sz, Payload: payload}
		if _, err := encVar.EncodeDataShortVar(&bufVar, fVar); err != nil {
			t.Fatalf("EncodeDataShortVar(sz=%d): %v", sz, err)
		}
		decVar := NewCompressor()
		gotVar, err := decVar.DecodeDataShortVar(bytes.NewReader(bufVar.Bytes()[1:])) // strip indicator
		if err != nil {
			t.Fatalf("DecodeDataShortVar(sz=%d): %v", sz, err)
		}
		if gotVar.Length != sz {
			t.Errorf("DecodeDataShortVar(sz=%d): Length=%d", sz, gotVar.Length)
		}
		if !bytes.Equal(gotVar.Payload, payload) {
			t.Errorf("DecodeDataShortVar(sz=%d): payload mismatch", sz)
		}
	}
}

// AE-P-31: the MaxPayloadSize oversize guard still fires before any large
// allocation (the fix must not weaken the existing cap).
func TestAEP31_OversizeGuardUnchanged(t *testing.T) {
	const declared = uint32(MaxPayloadSize) + 1
	hdr := aep31shortHeader(0, 0, declared)

	c := NewCompressor()
	var err error
	delta := aep31allocDelta(func() {
		_, err = c.DecodeDataShort(bytes.NewReader(hdr))
	})
	if err == nil {
		t.Fatalf("DecodeDataShort: expected 'too large' error for length %d", declared)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("DecodeDataShort: error = %q, want mention of 'too large'", err.Error())
	}
	if delta > 1<<20 {
		t.Errorf("oversize guard allocated %d bytes before erroring — must reject before allocating", delta)
	}
}

// AE-P-31: a header declaring a large payload with a short/truncated body must
// error cleanly (no panic), even when the first prealloc chunk arrives.
func TestAEP31_PartialBody_ErrorsCleanly(t *testing.T) {
	const declared = uint32(1 << 20)
	hdr := aep31shortHeader(0, 0, declared)
	// Supply exactly one prealloc chunk of body, then EOF.
	body := aep31payload(maxShortPayloadPrealloc)

	r := bytes.NewReader(append(append([]byte{}, hdr...), body...))
	c := NewCompressor()
	got, err := c.DecodeDataShort(r)
	if err == nil {
		t.Fatalf("DecodeDataShort: expected error for truncated body (declared %d, body %d)", declared, len(body))
	}
	if got != nil {
		t.Errorf("DecodeDataShort: expected nil frame on truncated body, got %+v", got)
	}
}
