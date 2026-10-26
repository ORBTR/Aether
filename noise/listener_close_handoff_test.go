//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// TestNoiseListener_ClosedRightAfterADialHandsOffOrEnds: a listener closed
// the moment its peer's Dial returns, with nothing accepting at that moment,
// is the shape in which the responder's accept hand-off (handOffSession,
// spawned by handleHandshake once msg3 is read, since the initiator is done
// when it has written msg3) and the end of the listener's run loop overlap.
// The hand-off then either reaches the Accept that arrives afterwards or is
// dropped when the listener's closed channel closes; Accept after the close
// returns the handed-off session when one is queued and then io.EOF, inside
// the hand-off timeout, and never a nil session with a nil error. The -race
// detector is the verdict on the overlap itself; the assertions pin that the
// close completes and that one dial yields at most one accepted session. The
// loop gives the detector several interleavings in one run.
func TestNoiseListener_ClosedRightAfterADialHandsOffOrEnds(t *testing.T) {
	for i := 0; i < 12; i++ {
		server := wvTransport(t, nil, nil)
		client := wvTransport(t, nil, nil)
		serverLn, err := server.Listen(context.Background())
		if err != nil {
			t.Fatalf("round %d: server listen: %v", i, err)
		}
		clientLn, err := client.Listen(context.Background())
		if err != nil {
			t.Fatalf("round %d: client listen: %v", i, err)
		}
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := client.Dial(dialCtx, aether.Target{Address: serverLn.Addr().String(), NodeID: server.localNode})
		dialCancel()
		if err != nil {
			t.Fatalf("round %d: dial: %v", i, err)
		}
		// Close as soon as the dial returns: the responder may still be reading
		// msg3 and spawning its hand-off while the run loop ends.
		_ = serverLn.Close()

		acceptCtx, acceptCancel := context.WithTimeout(context.Background(), acceptHandoffTimeout+2*time.Second)
		accepted := 0
		for {
			s, err := serverLn.Accept(acceptCtx)
			if err == nil {
				if s == nil {
					t.Fatalf("round %d: Accept after Close returned no session and no error", i)
				}
				accepted++
				_ = s.Close()
				if accepted > 1 {
					t.Fatalf("round %d: one dial yielded %d accepted sessions", i, accepted)
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("round %d: Accept after Close returned %v, want io.EOF", i, err)
		}
		acceptCancel()
		_ = c.Close()
		_ = clientLn.Close()
	}
}
