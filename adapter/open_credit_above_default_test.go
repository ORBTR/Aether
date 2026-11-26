//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether/flow"
)

// TestNoiseStream_AnOpenerWithMoreCreditThanTheDefaultIsAdmitted: an opener
// holding 2 MiB of credit, more than the accepting side's own default
// (flow.DefaultStreamCredit), sends 1.5 MiB with no reader on the other end.
// The burst is acknowledged, both ends stay open, and the reader then gets
// every message. The accepted stream's queue bound is receiveCeilings' stream
// limit, the window handleOpen builds from the OPEN's InitialCredit; a bound
// taken from the accepting side's own default would put this honest sender
// past it, and enqueueDelivery would reset the stream with ResetFlowCtrl and
// charge the peer as ignoring credit.
func TestNoiseStream_AnOpenerWithMoreCreditThanTheDefaultIsAdmitted(t *testing.T) {
	const (
		credit = 2 << 20
		size   = 64 * 1024
		count  = 24
	)
	if int64(count*size) <= flow.DefaultStreamCredit || int64(count)*messageCredit(size) > credit {
		t.Fatalf("premise: %d messages of %d bytes must pass the default credit %d and fit the opener's %d",
			count, size, flow.DefaultStreamCredit, credit)
	}
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 130, credit)
	msg := make([]byte, size)
	for i := 0; i < count; i++ {
		if err := cs.Send(ctx, msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitSendWindowEmpty(t, cs, "the burst acknowledged")
	time.Sleep(200 * time.Millisecond)
	if !ss.IsOpen() || !cs.IsOpen() {
		t.Fatalf("an honest opener holding %d of credit was reset after %d bytes (accepted stream's window %d)",
			credit, count*size, ss.window.CurrentWindow())
	}
	for i := 0; i < count; i++ {
		if got, err := ss.Receive(ctx); err != nil || len(got) != size {
			t.Fatalf("receive %d: %d bytes, %v", i, len(got), err)
		}
	}
}
