/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package flow

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestConsumeUntil_TheDoneChannelEndsTheWait: a credit wait on an empty stream or
// connection window ends when its done channel closes, answering ErrWaitEnded and not
// ErrCreditExhausted, with nothing charged; a nil done leaves Consume's wait as it is,
// ending at the context.
func TestConsumeUntil_TheDoneChannelEndsTheWait(t *testing.T) {
	stream := NewStreamWindow(MinGuaranteedWindow)
	conn := NewConnWindow(MinGuaranteedWindow)
	if err := stream.Consume(context.Background(), MinGuaranteedWindow); err != nil {
		t.Fatalf("stream fill: %v", err)
	}
	if err := conn.Consume(context.Background(), conn.Available()); err != nil {
		t.Fatalf("conn fill: %v", err)
	}
	for _, w := range []struct {
		name    string
		consume func(context.Context, int64, <-chan struct{}) error
		charged func() int64
	}{
		{"stream", stream.ConsumeUntil, stream.Outstanding},
		{"connection", conn.ConsumeUntil, func() int64 { return conn.Stats().Outstanding }},
	} {
		before := w.charged()
		done := make(chan struct{})
		got := make(chan error, 1)
		start := time.Now()
		go func() { got <- w.consume(context.Background(), 1, done) }()
		time.Sleep(50 * time.Millisecond)
		close(done)
		select {
		case err := <-got:
			if !errors.Is(err, ErrWaitEnded) || errors.Is(err, ErrCreditExhausted) {
				t.Fatalf("%s: %v, want ErrWaitEnded", w.name, err)
			}
		case <-time.After(ConsumeTimeout / 2):
			t.Fatalf("%s: the wait outlived its done channel by %s", w.name, time.Since(start))
		}
		if after := w.charged(); after != before {
			t.Fatalf("%s: charge went from %d to %d on an ended wait", w.name, before, after)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := w.consume(ctx, 1, nil)
		cancel()
		if !errors.Is(err, ErrCreditExhausted) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s with no done: %v, want the backpressure and the context's end", w.name, err)
		}
	}
}
