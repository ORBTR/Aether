/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"bytes"
	"errors"
	"testing"
)

// TestShortForms_AnEncryptedDataFormIsReadOnlyWhereAFrameKeyCanAuthenticateIt: 0x87's
// payload is a [Nonce][Ciphertext][Tag] envelope only a frame key authenticates, so a
// session that installed none (every TCPSession, a NoiseSession without
// SetSessionKey) refuses it at its first byte as it refuses a form it did not choose,
// before reading the header, and never hands its payload on as plaintext. A decoder
// whose session installed a key (AcceptEncryptedShort) reads it.
func TestShortForms_AnEncryptedDataFormIsReadOnlyWhereAFrameKeyCanAuthenticateIt(t *testing.T) {
	wire := func() *bytes.Reader {
		envelope := bytes.Repeat([]byte{0xA5}, 12+5+16)
		hdr := []byte{ShortEncryptedIndicator, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, byte(len(envelope))}
		return bytes.NewReader(append(hdr, envelope...))
	}
	keyless := shortFormCompressor(t)
	keyless.RecordFullHeader(&Frame{StreamID: 5, Type: TypeDATA})
	r := wire()
	f, _, _, err := ReadNextFrame(r, keyless)
	var de *FrameDiscriminatorError
	if f != nil || !errors.As(err, &de) || de.Discriminator != ShortEncryptedIndicator {
		t.Fatalf("a session with no frame key read 0x87 as %+v, %v; want the discriminator refusal", f, err)
	}
	if r.Len() != 8+12+5+16 {
		t.Fatalf("the refusal read %d bytes past the indicator", 8+12+5+16-r.Len())
	}

	keyed := shortFormCompressor(t)
	keyed.RecordFullHeader(&Frame{StreamID: 5, Type: TypeDATA})
	keyed.AcceptEncryptedShort()
	f, indicator, _, err := ReadNextFrame(wire(), keyed)
	if err != nil || f == nil || indicator != ShortEncryptedIndicator || len(f.Payload) != 12+5+16 {
		t.Fatalf("a session with a frame key read 0x87 as %+v, 0x%02x, %v", f, indicator, err)
	}
}
