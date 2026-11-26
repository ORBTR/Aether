/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
	aethercrypto "github.com/ORBTR/aether/crypto"
	"github.com/ORBTR/aether/pmtu"
)

// TestMSSToMaxPayload_ASealedFullFrameIsTheMSS: at every MSS the prober can hold, a
// DATA frame carrying MSSToMaxPayload's payload, sealed by the FrameEncryptor a
// NoiseSession seals with and written as a full frame (EncodeFrame, the form
// encodeFrameLocked falls back to), is exactly the MSS long: no frame noiseStream.Send
// writes without FEC is longer than the path the prober measured.
func TestMSSToMaxPayload_ASealedFullFrameIsTheMSS(t *testing.T) {
	var key [32]byte
	key[0] = 7
	enc, err := aethercrypto.NewFrameEncryptor(key, true)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	for _, mss := range []int{pmtu.SafeFloorMSS, 1280, 1400, 1500, 2000, 4000, 8000} {
		payload := make([]byte, MSSToMaxPayload(mss))
		frame := &aether.Frame{
			StreamID: 100,
			Type:     aether.TypeDATA,
			Length:   uint32(len(payload)),
			Payload:  payload,
		}
		if err := enc.Encrypt(frame); err != nil {
			t.Fatalf("MSS %d: seal: %v", mss, err)
		}
		var buf bytes.Buffer
		if _, err := aether.EncodeFrame(&buf, frame); err != nil {
			t.Fatalf("MSS %d: encode: %v", mss, err)
		}
		if buf.Len() != mss {
			t.Errorf("MSS %d: a sealed full DATA frame of MSSToMaxPayload's %d B payload is %d B on the wire, want the MSS",
				mss, len(payload), buf.Len())
		}
	}
}
