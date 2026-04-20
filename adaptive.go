/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"runtime"
	"sync"
	"time"
)

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
	opts SessionOptions
	enabled        bool
	checkInterval  time.Duration
	lastCPUPercent float64
	stopCh         chan struct{}
}

// NewAdaptiveController creates a controller that monitors CPU and degrades features.
func NewAdaptiveController(opts SessionOptions) *AdaptiveController {
	return &AdaptiveController{
		opts:          opts,
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

	// Estimate CPU utilization from goroutine count and GOMAXPROCS.
	// This is a rough heuristic — production should use runtime/pprof or cgroup stats.
	goroutines := runtime.NumGoroutine()
	maxProcs := runtime.GOMAXPROCS(0)
	// Rough estimate: if goroutines >> maxProcs, CPU is likely saturated.
	// This is imprecise but works as a fast check without OS-specific APIs.
	estimated := float64(goroutines) / float64(maxProcs*10) * 100
	if estimated > 100 {
		estimated = 100
	}

	a.mu.Lock()
	a.lastCPUPercent = estimated
	a.mu.Unlock()

	// Apply degradation rules — disable features as CPU increases.
	// SessionOptions uses positive flags (true=enabled), so we set to false to disable.
	// NOTE: Encryption is NOT included — it is a security invariant that must never degrade.

	if estimated > 90 && a.opts.Scheduler {
		a.opts.Scheduler = false
		dbgAether.Printf("Adaptive CPU %.0f%% > 90%%: disabling WFQ scheduler (using FIFO)", estimated)
	} else if estimated <= 85 && !a.opts.Scheduler {
		a.opts.Scheduler = true
	}

	if estimated > 80 && a.opts.FEC {
		a.opts.FEC = false
		dbgAether.Printf("Adaptive CPU %.0f%% > 80%%: disabling FEC", estimated)
	} else if estimated <= 75 && !a.opts.FEC {
		a.opts.FEC = true
	}

	if estimated > 70 && a.opts.Compression {
		a.opts.Compression = false
		dbgAether.Printf("Adaptive CPU %.0f%% > 70%%: disabling compression", estimated)
	} else if estimated <= 65 && !a.opts.Compression {
		a.opts.Compression = true
	}
}
