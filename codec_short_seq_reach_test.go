/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"bytes"
	"testing"
)

// TestShortForms_ASeqNoGapTheDecoderCannotRebuildTakesTheFullHeader: a short DATA form
// carries the low 16 bits of its SeqNo, which the receiver rebuilds as the closest value
// to the one after its last (reconstructSeqNo), so the sender writes one only for a SeqNo
// 0 to maxShortSeqGap above its last and the full header past that. Each gap is put to
// a sender and a receiver whose last SeqNo is the same: a gap inside the reach is
// written short and rebuilt exactly, and one past it, up to the 16-bit field's own
// range and beyond, is kept on the full header.
func TestShortForms_ASeqNoGapTheDecoderCannotRebuildTakesTheFullHeader(t *testing.T) {
	for _, tc := range []struct {
		gap   uint32
		short bool
	}{
		{0, true}, {1, true}, {maxShortSeqGap, true},
		{maxShortSeqGap + 1, false}, {32769, false}, {40000, false}, {65535, false}, {65536, false},
	} {
		tx, rx := shortFormCompressor(t), shortFormCompressor(t)
		base := &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70000, Length: 1, Payload: []byte{1}}
		tx.RecordFullHeader(base)
		rx.RecordFullHeader(base)
		f := &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70000 + tc.gap, Length: 3, Payload: []byte{1, 2, 3}}
		if got := tx.ShouldCompressData(f); got != tc.short {
			t.Fatalf("gap %d: ShouldCompressData = %v, want %v", tc.gap, got, tc.short)
		}
		if !tc.short {
			continue
		}
		var b bytes.Buffer
		if _, err := tx.EncodeDataShort(&b, f); err != nil {
			t.Fatalf("gap %d: encode: %v", tc.gap, err)
		}
		got, err := rx.DecodeDataShort(bytes.NewReader(b.Bytes()[1:]))
		if err != nil {
			t.Fatalf("gap %d: decode: %v", tc.gap, err)
		}
		if got.SeqNo != f.SeqNo {
			t.Fatalf("gap %d: sent SeqNo %d in a short form, the receiver rebuilt %d", tc.gap, f.SeqNo, got.SeqNo)
		}
	}
}
