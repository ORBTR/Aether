/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
// false-triggers load-shedding (AER-025).
const adaptiveGoroutineFloor = 2000

// AdaptiveController monitors system load and dynamically disables
// expensive Aether features when CPU is saturated.
//
// Degradation order (progressive):
//  1. CPU > 70%: disable DEFLATE compression
//  2. CPU > 80%: disable FEC
//  3. CPU > 90%: reduce scheduler to simple round-robin
//
// Encryption is NEVER disabled — it is a security invariant.
// See docs/_SECURITY.md §3.10 for the threat model justification.
type AdaptiveController struct {
	mu             sync.RWMutex
	sessions       map[CompressionCapable]struct{} // AE-L-03: live sessions this controller sheds load from
	enabled        bool
	checkInterval  time.Duration
	lastCPUPercent float64
	fecDegraded    bool // AE-L-03: current FEC rung decision (monitoring / future runtime FECCapable toggle)
	schedDegraded  bool // AE-L-03: current scheduler rung decision (monitoring / future runtime SchedulerCapable toggle)
	stopCh         chan struct{}
}

// NewAdaptiveController creates a controller that monitors CPU and degrades
// features. Register live sessions via Register so check() can shed their
// load; call Unregister on session close. AE-L-03.
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

// Stop halts the adaptive controller.
func (a *AdaptiveController) Stop() {
	close(a.stopCh)
}

// Register enrols a runtime-toggleable session so the controller can shed its
// load under CPU pressure. Sessions whose transport has no per-frame DEFLATE
// simply don't implement CompressionCapable and aren't registered. Safe for
// concurrent use. AE-L-03.
func (a *AdaptiveController) Register(s CompressionCapable) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[s] = struct{}{}
}

// Unregister drops a session from the degrade set on close. AE-L-03.
func (a *AdaptiveController) Unregister(s CompressionCapable) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, s)
}

// setEnabled toggles adaptive degradation on/off.
func (a *AdaptiveController) setEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

// cpuPercent returns the last measured CPU utilization (0-100).
func (a *AdaptiveController) cpuPercent() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lastCPUPercent
}

// check measures CPU and applies degradation rules.
// Encryption is intentionally excluded — disabling it under load
// would create an exploitable attack vector (see §3.10).
func (a *AdaptiveController) check() {
	a.mu.Lock()
	if !a.enabled {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	// AER-025: goroutine count is a POOR proxy for CPU. Each Noise/TCP session
	// spawns several goroutines, so the old goroutines/(maxProcs*10) formula
	// read as permanently "saturated" on any node with more than ~2×maxProcs
	// sessions and disabled compression fleet-wide — a bandwidth cost, not a
	// real load response. Until a real CPU source (cgroup/pprof) is wired,
	// only a genuine goroutine EXPLOSION (far beyond normal per-session
	// counts) is treated as pressure, scaling from a high floor so ordinary
	// operation reads as unloaded and the safe default (compression on) holds.
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
// Encryption is intentionally never toggled — security invariant (§3.10).
// AE-L-03: previously this block mutated a private by-value SessionOptions
// copy (a.opts) that no session ever read, so the ladder was inert.
func (a *AdaptiveController) applyDegradation(estimated float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastCPUPercent = estimated

	// Rung 1 (>70%): disable per-frame DEFLATE on every registered session
	// via the atomic runtime toggle the encode path samples per frame
	// (noise_session.go compressionEnabled). This IS the shared,
	// atomically-read policy sessions actually consult — unlike the old
	// detached a.opts copy. Restore below 65% (hysteresis avoids flap).
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
	// be flipped on a live session yet. Record the rung decision here —
	// consumed by monitoring and by the future runtime FECCapable /
	// SchedulerCapable toggles — so the documented three-rung ladder is
	// preserved and testable. Enforcement wiring is a tracked follow-up.
	// No capability is removed: these rungs are inert today regardless.
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
