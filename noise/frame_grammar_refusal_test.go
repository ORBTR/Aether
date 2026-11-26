//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package noise

import (
	"context"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// TestNoiseResponder_RefusesAnInitiatorOfferingOnlyTheEarlierFrameGrammar: a
// msg3 whose NodeInfo offers the frame grammar before this build's, and every
// other entry as this build offers it, completes no session at the responder,
// which registers nothing for the initiator and counts the refusal; the same
// hand-built initiator with this build's offer is accepted and both sides'
// set names the current frame grammar, so the refusal is the frame entry's.
func TestNoiseResponder_RefusesAnInitiatorOfferingOnlyTheEarlierFrameGrammar(t *testing.T) {
	local, _ := aether.LocalWireVersions(nil)
	earlier := make(aether.WireVersions, len(local))
	for i, e := range local {
		earlier[i] = e
		if e.Name == aether.WireVersionFrame {
			earlier[i].Versions = []uint16{aether.WireVersionFrameCurrent - 1}
		}
	}
	for _, tc := range []struct {
		name    string
		offer   aether.WireVersions
		accepts bool
	}{
		{name: "current grammar", offer: local, accepts: true},
		{name: "earlier grammar only", offer: earlier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := wvTransport(t, nil, nil)
			ln, err := resp.Listen(context.Background())
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() {
				if err := ln.Close(); err != nil {
					t.Errorf("ln.Close: %v", err)
				}
			}()
			h := newHandInitiator(t)
			dst := ln.Addr().(*net.UDPAddr)
			if err := h.run(dst, nodeInfoWithout(t, h.id, tc.offer)); err != nil {
				t.Fatalf("hand initiator: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			s, err := ln.Accept(ctx)
			if tc.accepts {
				if err != nil {
					t.Fatalf("control arm accepted nothing: %v", err)
				}
				got := chosenOn(t, s)
				if v, ok := got.Version(aether.WireVersionFrame); !ok || v != aether.WireVersionFrameCurrent {
					t.Fatalf("control arm chose frame %d, %v", v, ok)
				}
				_ = s.Close()
				return
			}
			if err == nil {
				t.Fatalf("responder accepted a session from an initiator of the earlier frame grammar")
			}
			if resp.listener.sessions.Get(h.id.NodeID) != nil {
				t.Fatalf("responder registered a session for the refused initiator")
			}
			if got := resp.listener.DropSnapshot()[DropWireVersionMismatch.String()]; got == 0 {
				t.Fatalf("refusal not counted under %s", DropWireVersionMismatch)
			}
		})
	}
}
