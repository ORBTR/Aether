/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"testing"
)

// ─── AE-P-27 — encrypted-data-short (0x87) sub-frame inside a batch ─────────
//
// A batched 0x87 sub-frame decodes (via DecodeEncryptedDataShort →
// DecodeDataShort) to a Type=DATA frame with NO FlagENCRYPTED, while the OUTER
// batch indicator (0x85) is what reaches processIncomingFrame. Neither decrypt
// gate (indicator==0x87 / FlagENCRYPTED) then fires, so the raw
// [Nonce||Ciphertext||Tag] payload would be delivered to the app undecrypted.
// The honest encoder never batches encrypted frames (EncodeBatch routes DATA
// through ShouldCompressData, which excludes FlagENCRYPTED), so a batched 0x87
// can only come from a crafted or buggy peer. DecodeBatch now fails closed.

// TestAEP27_BatchedEncryptedSubFrameRejected drives a batch whose single
// sub-frame is a 0x87 encrypted-data-short and asserts DecodeBatch errors
// instead of surfacing the undecrypted payload.
func TestAEP27_BatchedEncryptedSubFrameRejected(t *testing.T) {
	body := aep27BatchBody(t, func(enc *Compressor, w *bytes.Buffer) {
		f := &Frame{
			StreamID: 3,
			SeqNo:    1,
			Type:     TypeDATA,
			Length:   40, // stand-in for [Nonce:12][Ciphertext][Tag:16]
			Payload:  make([]byte, 40),
		}
		if _, err := enc.EncodeEncryptedDataShort(w, f); err != nil {
			t.Fatalf("encode 0x87 sub-frame: %v", err)
		}
	})

	dec := NewCompressor()
	frames, err := dec.DecodeBatch(bytes.NewReader(body))
	if err == nil {
		t.Fatalf("AE-P-27 regressed: batched 0x87 sub-frame accepted (got %d frame(s)); "+
			"raw undecrypted [Nonce||Ciphertext||Tag] would reach the app", len(frames))
	}
	if !bytes.Contains([]byte(err.Error()), []byte("0x87")) {
		t.Fatalf("AE-P-27: expected an 0x87-in-batch rejection error, got: %v", err)
	}
}

// TestAEP27_BatchedPlainDataStillDecodes is the non-regression control: a batch
// of plain DATA sub-frames must still decode cleanly — the fix rejects only the
// encrypted-short indicator, not the whole batch path.
func TestAEP27_BatchedPlainDataStillDecodes(t *testing.T) {
	body := aep27BatchBody(t, func(enc *Compressor, w *bytes.Buffer) {
		f := &Frame{
			StreamID: 3,
			SeqNo:    1,
			Type:     TypeDATA,
			Length:   8,
			Payload:  []byte("aep27ctl"),
		}
		if _, err := enc.EncodeDataShort(w, f); err != nil {
			t.Fatalf("encode 0x82 sub-frame: %v", err)
		}
	})

	dec := NewCompressor()
	frames, err := dec.DecodeBatch(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("AE-P-27 control: plain-DATA batch failed to decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("AE-P-27 control: got %d frames, want 1", len(frames))
	}
}

// aep27BatchBody produces the bytes DecodeBatch consumes: a 1-byte count
// followed by exactly one sub-frame written by writeSub. The leading 0x85 batch
// indicator is consumed by the caller before DecodeBatch, so it is omitted.
func aep27BatchBody(t *testing.T, writeSub func(enc *Compressor, w *bytes.Buffer)) []byte {
	t.Helper()
	enc := NewCompressor()
	var sub bytes.Buffer
	writeSub(enc, &sub)

	var batch bytes.Buffer
	batch.WriteByte(0x01) // sub-frame count = 1
	batch.Write(sub.Bytes())
	return batch.Bytes()
}
