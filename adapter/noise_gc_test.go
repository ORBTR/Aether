//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"testing"

	"github.com/ORBTR/aether"
)

// AE-H-10 regression coverage. Per-stream GC activity used to be refreshed
// only on inbound DATA (handleData); dispatchFrame recorded nothing for
// ACK / WINDOW_UPDATE. An upload-only stream sees only ACK/WINDOW frames
// returning on its app stream, so after the 5-min idle timeout the sweep
// RESET its own actively-transmitting stream mid-transfer and the next
// Send failed. The fix moves the refresh to dispatchFrame (mirroring
// adapter/tcp.go) so ANY frame on a non-control stream is liveness.
//
// This test drives dispatchFrame with a bare ACK on an unknown app stream
// and asserts StreamGC now tracks it. Pre-fix the ACK recorded nothing —
// TrackedCount would be 0. The ACK targets an unregistered stream so
// handleACK returns early after the streams-map lookup (no BaseSession
// deref, no panic), keeping the assertion deterministic and lock-free of
// any background sweep timing.
func TestNoiseDispatch_ACKRefreshesStreamGC(t *testing.T) {
	s := &NoiseSession{streams: make(map[uint64]*noiseStream)}
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(uint64) {})

	if got := s.streamGC.TrackedCount(); got != 0 {
		t.Fatalf("precondition: TrackedCount = %d, want 0", got)
	}

	// Inbound ACK on an app stream (>=10) that was never Registered. The
	// central dispatchFrame refresh must record it as GC activity.
	s.dispatchFrame(&aether.Frame{Type: aether.TypeACK, StreamID: 100})

	if got := s.streamGC.TrackedCount(); got != 1 {
		t.Fatalf("after ACK dispatch: TrackedCount = %d, want 1 "+
			"(AE-H-10 regressed: ACK frame did not refresh stream GC)", got)
	}

	// A control-stream frame (StreamID 0) must NOT be recorded — the guard
	// mirrors tcp.go and preserves the control-stream GC exemption.
	s.dispatchFrame(&aether.Frame{Type: aether.TypeACK, StreamID: 0})
	if got := s.streamGC.TrackedCount(); got != 1 {
		t.Fatalf("control-stream frame recorded activity: TrackedCount = %d, want 1", got)
	}
}
