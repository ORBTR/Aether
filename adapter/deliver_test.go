//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package adapter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether/flow"
)

// End-to-end assertion that application-read-driven grants produce real
// backpressure: a slow consumer takes meaningfully longer to refill the
// sender's credit than a fast consumer. That's what application-level
// backpressure MEANS — credit availability on the sender side tracks
// the receiver's actual consumption rate, not the arrival rate of
// frames into recvCh. If grants emitted as soon as a frame landed in
// recvCh, a slow consumer would give no signal to the sender at all.
//
// Strategy:
//   - Sender drains its full 4 MB window with 20 × 128 KB payloads.
//   - Receiver consumes those bytes at two different paces, calling
//     Record on each read (mirroring noiseStream.Receive).
//   - Measure elapsed time from workload start until Available()
//     returns to a "credit refilled past half window" state.
//   - Assert: slow reader's refill-time ≥ fast reader's refill-time.
func TestConsumeDrivenGrants_SlowConsumerBackpressuresSender(t *testing.T) {
	const (
		window      = 4 * 1024 * 1024
		payloadSize = 128 * 1024
		payloads    = 20 // 2.5 MB total, under the window
	)

	// Helper: construct a StreamWindow, consume the full workload amount
	// on the sender side, then let the receiver drain recvCh at
	// readInterval, recording each read. Returns elapsed time until the
	// sender's Available() crosses the 2MB mark (half-window refilled).
	run := func(readInterval time.Duration) time.Duration {
		w := flow.NewStreamWindow(window)
		// Install an updater that applies grants back to the window, so
		// refill actually happens and Available() tracks real refill.
		var mu sync.Mutex
		var applied int64
		send := func(sid uint64, credit uint64) {
			mu.Lock()
			applied = int64(credit)
			mu.Unlock()
			w.ApplyUpdate(int64(credit))
		}
		d := newGrantDebouncer(w, send, 42,
			int64(float64(window)*GrantImmediateFraction))
		defer d.Close()

		// Sender consumes all payload bytes up front.
		if err := w.Consume(context.Background(), payloadSize*payloads); err != nil {
			t.Fatalf("consume: %v", err)
		}

		// Now dispatch payloads into recvCh for the consumer to drain.
		recvCh := make(chan []byte, 64)
		go func() {
			for i := 0; i < payloads; i++ {
				recvCh <- make([]byte, payloadSize)
			}
			close(recvCh)
		}()

		start := time.Now()

		// Consumer: reads + records at readInterval.
		done := make(chan struct{})
		go func() {
			defer close(done)
			for payload := range recvCh {
				if readInterval > 0 {
					time.Sleep(readInterval)
				}
				d.Record(int64(len(payload)))
			}
		}()

		// Wait until Available() crosses the half-window mark — that's
		// the moment enough grants have made it back to the sender that
		// it can resume a meaningful workload.
		halfWindow := int64(window / 2)
		deadline := time.After(2 * time.Second)
		for {
			if w.Available() >= halfWindow {
				return time.Since(start)
			}
			select {
			case <-deadline:
				<-done
				t.Fatalf("timeout waiting for half-window refill; readInterval=%v Available=%d applied=%d",
					readInterval, w.Available(), applied)
			case <-time.After(time.Millisecond):
			}
		}
	}

	fast := run(0)
	slow := run(10 * time.Millisecond)

	t.Logf("refill-to-half: fast=%v, slow=%v", fast, slow)

	// Backpressure assertion: a 10 ms-per-payload slow consumer MUST
	// take noticeably longer to refill than an instant consumer. If
	// they're the same, grant emission is no longer driven by
	// application reads — meaning the sender gets credit regardless of
	// whether the application has consumed anything.
	if slow < fast {
		t.Errorf("slow consumer refilled FASTER than fast (%v < %v) — should never happen",
			slow, fast)
	}
	if slow <= fast+5*time.Millisecond {
		t.Errorf("slow consumer should take meaningfully longer to refill: fast=%v slow=%v (diff=%v)",
			fast, slow, slow-fast)
	}
}

// Silence unused-import when the test is trimmed during debugging.
var _ atomic.Int32
