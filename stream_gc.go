/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"sync"
	"time"
)

// DefaultStreamIdleTimeout is the duration after which an idle stream is auto-reset.
// Well-known streams (IDs < StreamGCExemptBelow, i.e. 0-9) are exempt from idle timeout.
const DefaultStreamIdleTimeout = 5 * time.Minute

// StreamGCExemptBelow is the exclusive upper bound of stream IDs exempt from idle GC.
// AE-I-02: single source of truth for the sweep() exemption boundary so the code and
// docs cannot drift. Streams with ID < StreamGCExemptBelow (0-9) are well-known protocol
// streams (gossip, RPC, keepalive, control) and are never idle-reset; dynamic application
// streams use higher IDs.
const StreamGCExemptBelow = 10

// StreamGC garbage-collects idle streams to prevent resource leaks.
// Streams with no Send/Receive activity for StreamIdleTimeout are auto-RESET.
// Well-known streams (IDs < StreamGCExemptBelow, i.e. 0-9) are exempt.
type StreamGC struct {
	mu           sync.Mutex
	lastActivity map[uint64]time.Time // streamID → last activity timestamp
	idleTimeout  time.Duration
	resetFn      func(streamID uint64) // callback to reset idle stream
	stopCh       chan struct{}
	stopOnce     sync.Once
}

// NewStreamGC creates a stream garbage collector.
// resetFn is called for each stream that exceeds the idle timeout.
func NewStreamGC(idleTimeout time.Duration, resetFn func(streamID uint64)) *StreamGC {
	if idleTimeout <= 0 {
		idleTimeout = DefaultStreamIdleTimeout
	}
	return &StreamGC{
		lastActivity: make(map[uint64]time.Time),
		idleTimeout:  idleTimeout,
		resetFn:      resetFn,
		stopCh:       make(chan struct{}),
	}
}

// RecordActivity marks a stream as active (called on every Send/Receive).
func (g *StreamGC) RecordActivity(streamID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastActivity[streamID] = time.Now()
}

// Register adds a stream to the GC tracker.
func (g *StreamGC) Register(streamID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastActivity[streamID] = time.Now()
}

// Unregister removes a stream from the GC tracker (already closed).
func (g *StreamGC) Unregister(streamID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.lastActivity, streamID)
}

// Start begins the periodic GC sweep. Call in a goroutine.
func (g *StreamGC) Start() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.sweep()
		}
	}
}

// Stop halts the GC. Idempotent — safe to call multiple times and from
// multiple goroutines. Exiting the goroutine breaks the root chain that
// pinned the owning session via resetFn's closure.
func (g *StreamGC) Stop() {
	g.stopOnce.Do(func() {
		close(g.stopCh)
	})
}

// sweep checks all tracked streams for idle timeout.
func (g *StreamGC) sweep() {
	g.mu.Lock()
	now := time.Now()
	var expired []uint64
	for streamID, lastSeen := range g.lastActivity {
		// AE-I-02: exempt well-known low stream IDs (gossip, RPC, keepalive,
		// control). Boundary lives in StreamGCExemptBelow so sweep() and the
		// type/const docs stay in sync. Dynamic application streams use higher IDs.
		if streamID < StreamGCExemptBelow {
			continue
		}
		if now.Sub(lastSeen) > g.idleTimeout {
			expired = append(expired, streamID)
		}
	}
	for _, id := range expired {
		delete(g.lastActivity, id)
	}
	g.mu.Unlock()

	// Reset expired streams outside the lock
	for _, id := range expired {
		dbgAether.Printf("Stream GC: resetting idle stream %d (timeout %v)", id, g.idleTimeout)
		if g.resetFn != nil {
			g.resetFn(id)
		}
	}
}

// TrackedCount returns the number of streams being tracked.
func (g *StreamGC) TrackedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.lastActivity)
}
