/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package aether

import "testing"

// TestShouldCompressACK_ASealedACKKeepsTheFullHeader: an ACK flagged FlagENCRYPTED,
// as NoiseSession writes every ACK once it holds a frame key, is refused the short
// forms, whose decoders give back no ENCRYPTED flag; the same ACK unsealed stays
// short-eligible.
func TestShouldCompressACK_ASealedACKKeepsTheFullHeader(t *testing.T) {
	c := shortFormCompressor(t)
	c.RecordFullHeader(&Frame{Type: TypeACK, StreamID: 1})

	sealed := &Frame{Type: TypeACK, StreamID: 1, Flags: FlagCOMPOSITE_ACK | FlagENCRYPTED,
		Length: 40, Payload: make([]byte, 40)}
	if c.ShouldCompressACK(sealed) {
		t.Error("ShouldCompressACK admitted a sealed ACK to a short form that carries no ENCRYPTED flag")
	}
	plain := *sealed
	plain.Flags = FlagCOMPOSITE_ACK
	if !c.ShouldCompressACK(&plain) {
		t.Error("an unsealed ACK on a pinned session must stay short-eligible")
	}
}
