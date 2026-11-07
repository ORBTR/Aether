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
// The single source of truth for the sweep() exemption boundary so the code and
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
	// sessionLifetime holds the IDs sweep never resets for being idle: the
	// session's SessionLifetimeStreams. Written only by NewSessionStreamGC, before
	// Start, so sweep reads it without the lock.
	sessionLifetime map[uint64]struct{}
	resetFn         func(streamID uint64) // callback to reset idle stream
	stopCh          chan struct{}
	stopOnce        sync.Once
}

// NewStreamGC creates a stream garbage collector.
// resetFn is called for each stream that exceeds the idle timeout.
func NewStreamGC(idleTimeout time.Duration, resetFn func(streamID uint64)) *StreamGC {
	if idleTimeout <= 0 {
		idleTimeout = DefaultStreamIdleTimeout
	}
	return &StreamGC{
		lastActivity:    make(map[uint64]time.Time),
		idleTimeout:     idleTimeout,
		sessionLifetime: make(map[uint64]struct{}),
		resetFn:         resetFn,
		stopCh:          make(chan struct{}),
	}
}

// NewSessionStreamGC is the stream GC a session runs under opts: streams idle for
// opts.StreamIdleTimeout are reset through resetFn, except the IDs below
// StreamGCExemptBelow and the IDs in opts.SessionLifetimeStreams, which live as long
// as the session. The TCP-family and Noise adapters both build their GC here, so the
// two read one rule for which streams outlive their idleness.
func NewSessionStreamGC(opts SessionOptions, resetFn func(streamID uint64)) *StreamGC {
	g := NewStreamGC(opts.StreamIdleTimeout, resetFn)
	for _, id := range opts.SessionLifetimeStreams {
		g.sessionLifetime[id] = struct{}{}
	}
	return g
}

// streamGCSweepCeiling and streamGCSweepFloor bound how far apart Start sweeps: half the
// idle timeout, so a stream is reset within one and a half idle timeouts of its last
// frame, never more than 30 s apart and never under 10 ms.
const (
	streamGCSweepCeiling = 30 * time.Second
	streamGCSweepFloor   = 10 * time.Millisecond
)

// sweepInterval is how far apart Start sweeps for this GC's idle timeout.
func (g *StreamGC) sweepInterval() time.Duration {
	every := g.idleTimeout / 2
	if every > streamGCSweepCeiling {
		return streamGCSweepCeiling
	}
	if every < streamGCSweepFloor {
		return streamGCSweepFloor
	}
	return every
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
	ticker := time.NewTicker(g.sweepInterval())
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
		// Exempt well-known low stream IDs (gossip, RPC, keepalive,
		// control). Boundary lives in StreamGCExemptBelow so sweep() and the
		// type/const docs stay in sync. Dynamic application streams use higher IDs.
		if streamID < StreamGCExemptBelow {
			continue
		}
		// A session-lifetime channel idles because its producer is caught up, not
		// because it was abandoned: both ends hold it open for the session, so a
		// reset here would end a live channel under its reader.
		if _, held := g.sessionLifetime[streamID]; held {
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
