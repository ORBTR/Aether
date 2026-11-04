/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// A frame the receive window gives up on after acknowledging it returns its
// sender's credit, and a CLOSE buffered behind it still ends the receive side, so
// the reader of a stream whose window runs SetMaxAge meets neither stranded credit
// nor a stream that never ends.
func TestNoiseStream_AnExpiredFrameReturnsItsCreditAndTheCloseStillEnds(t *testing.T) {
	sess := NewNoiseSession(newDiscardConn(), aether.NodeID("vl1_local_expired_aaaaaaaaaaaaaa"),
		aether.NodeID("vl1_remote_expired_bbbbbbbbbbbbb"), aether.DefaultSessionOptions())
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cs, err := sess.OpenStream(ctx, aether.StreamConfig{StreamID: 900, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := cs.(*noiseStream)
	st.recvWindow.SetMaxAge(time.Millisecond)

	const size = 1000
	data := func(seq uint32) *aether.Frame {
		return &aether.Frame{Type: aether.TypeDATA, StreamID: 900, SeqNo: seq, Length: size, Payload: make([]byte, size)}
	}
	sess.handleData(data(1))
	sess.handleClose(&aether.Frame{Type: aether.TypeCLOSE, StreamID: 900, SeqNo: 2})
	time.Sleep(5 * time.Millisecond)
	sess.handleData(data(0))

	if got := st.recvWindow.ExpiredCount(); got != 1 {
		t.Fatalf("ExpiredCount = %d, want the one buffered DATA frame", got)
	}
	if got := sess.deliveryStats.Dropped.Load(); got != 1 {
		t.Fatalf("Dropped = %d, want 1", got)
	}
	st.recvQ.mu.Lock()
	granted := st.recvQ.granted
	st.recvQ.mu.Unlock()
	if granted != messageCredit(size) {
		t.Fatalf("granted = %d, want the expired frame's credit %d", granted, messageCredit(size))
	}
	if _, err := cs.Receive(ctx); err != nil {
		t.Fatalf("receive the in-order message: %v", err)
	}
	if msg, err := cs.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("Receive after the buffered CLOSE = %d bytes, %v; want io.EOF", len(msg), err)
	}
}
