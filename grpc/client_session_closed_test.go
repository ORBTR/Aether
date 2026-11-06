/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestGrpcSession_SendOnAClosedSessionIsTyped: Send on a session that has closed,
// and a Send waiting on a full queue when the session closes, both answer
// aether.ErrSessionClosed, which a caller tells apart with errors.Is.
func TestGrpcSession_SendOnAClosedSessionIsTyped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	closed := newClientSession(nil)
	_ = closed.Close()
	if err := closed.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrSessionClosed) {
		t.Fatalf("Send after Close: %v, want aether.ErrSessionClosed", err)
	}

	waiting := newClientSession(nil)
	for i := 0; i < cap(waiting.sendCh); i++ {
		waiting.sendCh <- []byte("queued")
	}
	done := make(chan error, 1)
	go func() { done <- waiting.Send(ctx, []byte("waits")) }()
	time.Sleep(50 * time.Millisecond)
	_ = waiting.Close()
	select {
	case err := <-done:
		if !errors.Is(err, aether.ErrSessionClosed) {
			t.Fatalf("a Send waiting when the session closed: %v, want aether.ErrSessionClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("a Send waiting on a full queue did not return when the session closed")
	}
}
