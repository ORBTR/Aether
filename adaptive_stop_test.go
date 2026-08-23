package aether

import (
	"sync"
	"testing"
)

// Stop closes stopCh, which is the only channel the run loop selects on for
// termination. A bare close panics with "close of closed channel" on a second
// call, and Stop is exported on a published module, so the caller count is not
// this package's to bound — a consumer that stops a controller from both a
// shutdown path and a context-cancellation goroutine reaches it immediately.
func TestStopIsIdempotent(t *testing.T) {
	a := NewAdaptiveController()

	a.Stop()
	a.Stop() // the second call is the whole test; unguarded, this panics
	a.Stop()
}

// The concurrent shape, which is the one a bool or a check-then-act guard
// passes sequentially and fails here: several callers can observe "not yet
// stopped" before any close lands.
func TestStopIsSafeUnderConcurrentCallers(t *testing.T) {
	a := NewAdaptiveController()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Stop()
		}()
	}
	wg.Wait()
}

// Stop must still actually terminate the run loop — a guard that made Stop
// idempotent by never closing at all would pass both tests above while
// leaking the ticker goroutine for the process lifetime.
func TestStopActuallyClosesTheChannel(t *testing.T) {
	a := NewAdaptiveController()
	a.Stop()

	select {
	case <-a.stopCh:
		// closed, as the run loop requires
	default:
		t.Fatal("Stop returned without closing stopCh — the run loop's only " +
			"termination signal never fires, so its ticker goroutine outlives " +
			"every Stop and accumulates one per controller")
	}
}
