/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"runtime"
	"sync"
	"time"
)

// adaptiveGoroutineFloor is the goroutine count below which the (poor)
// goroutine-based CPU heuristic reports zero load. Sized well above a normal
// mesh node's per-session goroutine footprint so ordinary operation never
// false-triggers load-shedding (check).
const adaptiveGoroutineFloor = 2000

// AdaptiveController monitors system load and dynamically disables
// expensive Aether features when CPU is saturated.
//
// Degradation order (progressive):
//  1. CPU > 70%: disable DEFLATE compression
//  2. CPU > 80%: disable FEC
//  3. CPU > 90%: reduce scheduler to simple round-robin
//
// Encryption is NEVER disabled — it is a security invariant:
// applyDegradation touches only SetCompressionEnabled and the FEC /
// scheduler rung flags.
type AdaptiveController struct {
	mu             sync.RWMutex
	sessions       map[CompressionCapable]struct{} // live sessions this controller sheds load from (Register, applyDegradation)
	enabled        bool
	checkInterval  time.Duration
	lastCPUPercent float64
	fecDegraded    bool // current FEC rung decision (monitoring; TODO: a runtime FECCapable toggle)
	schedDegraded  bool // current scheduler rung decision (monitoring; TODO: a runtime SchedulerCapable toggle)
	stopCh         chan struct{}
	stopOnce       sync.Once // Stop is exported; concurrent callers must not double-close stopCh
}

// NewAdaptiveController creates a controller that monitors CPU and degrades
// features. Register live sessions via Register so check() can shed their
// load; call Unregister on session close.
func NewAdaptiveController() *AdaptiveController {
	return &AdaptiveController{
		sessions:      make(map[CompressionCapable]struct{}),
		enabled:       true,
		checkInterval: 5 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// Start begins CPU monitoring. Call in a goroutine.
func (a *AdaptiveController) Start() {
	ticker := time.NewTicker(a.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.check()
		}
	}
}

// Stop halts the adaptive controller. Idempotent and safe under concurrent
// callers.
//
// stopCh is the only thing the run loop selects on for termination, so Stop
// must close it — and a bare close panics with "close of closed channel" on a
// second call. Stop is exported on a published module, so the number of
// callers is not this file's to bound: the sibling WSConn.Close and
// StreamAcceptor.Close both guard their closes for the same reason.
func (a *AdaptiveController) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
}

// Register enrols a runtime-toggleable session so the controller can shed its
// load under CPU pressure. Sessions whose transport has no per-frame DEFLATE
// simply don't implement CompressionCapable and aren't registered. Safe for
// concurrent use.
func (a *AdaptiveController) Register(s CompressionCapable) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[s] = struct{}{}
}

// Unregister drops a session from the degrade set on close.
func (a *AdaptiveController) Unregister(s CompressionCapable) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, s)
}

// check measures CPU and applies degradation rules.
// Encryption is intentionally excluded — applyDegradation has no rung
// that touches it.
func (a *AdaptiveController) check() {
	a.mu.Lock()
	if !a.enabled {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	// Goroutine count is a POOR proxy for CPU. Each Noise/TCP session spawns
	// several goroutines, so a goroutines/(maxProcs*10) formula reads as
	// permanently "saturated" on any node with more than ~2×maxProcs sessions
	// and disables compression fleet-wide — a bandwidth cost, not a real load
	// response. Only a genuine goroutine EXPLOSION (far beyond normal
	// per-session counts) is treated as pressure, scaling from a high floor
	// (adaptiveGoroutineFloor) so ordinary operation reads as unloaded and the
	// safe default (compression on) holds.
	// TODO: a real CPU source (cgroup/pprof).
	goroutines := runtime.NumGoroutine()
	estimated := 0.0
	if goroutines > adaptiveGoroutineFloor {
		estimated = float64(goroutines-adaptiveGoroutineFloor) / float64(adaptiveGoroutineFloor) * 100
		if estimated > 100 {
			estimated = 100
		}
	}

	a.applyDegradation(estimated)
}

// applyDegradation drives the progressive load-shedding ladder against the
// LIVE registered sessions, under a.mu. Split out of check() so the rung
// thresholds are unit-testable without synthesizing real CPU load.
// Encryption is intentionally never toggled — security invariant.
// The ladder acts on the registered sessions (Register), the only thing a
// toggle reaches: a private options copy no session reads would leave it
// inert.
func (a *AdaptiveController) applyDegradation(estimated float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastCPUPercent = estimated

	// Rung 1 (>70%): disable per-frame DEFLATE on every registered session
	// via the atomic runtime toggle the encode path samples per frame
	// (noise_session.go compressionEnabled). This IS the shared,
	// atomically-read policy sessions consult. Restore below 65%
	// (hysteresis avoids flap).
	// SetCompressionEnabled is an atomic store and takes no lock of its
	// own, so calling it under a.mu cannot deadlock.
	if estimated > 70 {
		for s := range a.sessions {
			s.SetCompressionEnabled(false)
		}
		if len(a.sessions) > 0 {
			dbgAether.Printf("Adaptive CPU %.0f%% > 70%%: disabling compression on %d session(s)", estimated, len(a.sessions))
		}
	} else if estimated <= 65 {
		for s := range a.sessions {
			s.SetCompressionEnabled(true)
		}
	}

	// Rung 2 (>80%, FEC) and Rung 3 (>90%, WFQ scheduler) are sampled at
	// session-construction time (opts.FEC / scheduler build), so they cannot
	// be flipped on a live session. Record the rung decision here so the
	// three-rung ladder is testable.
	// TODO: wire fecDegraded and schedDegraded into the sessions' FEC and
	// scheduler toggles; until then the two rungs set their flags and change
	// nothing a session reads (the flags are unexported; only a test reads them).
	if estimated > 80 {
		a.fecDegraded = true
	} else if estimated <= 75 {
		a.fecDegraded = false
	}
	if estimated > 90 {
		a.schedDegraded = true
	} else if estimated <= 85 {
		a.schedDegraded = false
	}
}
