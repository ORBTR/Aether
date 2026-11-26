/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
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
	// registrations holds, for each tracked ID a session registered with RegisterAs,
	// the registration that tracks it; an ID tracked by Register or RecordActivity
	// has none (zero). UnregisterRegistration and sweep read it so that the ended
	// stream's release and the idle reset name one registration of the ID, not
	// whichever stream holds the ID when they run. Guarded by mu with lastActivity,
	// and holds no ID lastActivity does not.
	registrations map[uint64]uint64
	resetFn       func(streamID, registration uint64) // callback to reset idle stream
	stopCh        chan struct{}
	stopOnce      sync.Once
}

// NewStreamGC creates a stream garbage collector.
// resetFn is called for each stream that exceeds the idle timeout.
func NewStreamGC(idleTimeout time.Duration, resetFn func(streamID uint64)) *StreamGC {
	return newStreamGC(idleTimeout, byStreamID(resetFn))
}

// newStreamGC is the stream GC under idleTimeout (DefaultStreamIdleTimeout when not
// positive) that hands each idle stream's ID and registration to resetFn.
func newStreamGC(idleTimeout time.Duration, resetFn func(streamID, registration uint64)) *StreamGC {
	if idleTimeout <= 0 {
		idleTimeout = DefaultStreamIdleTimeout
	}
	return &StreamGC{
		lastActivity:    make(map[uint64]time.Time),
		idleTimeout:     idleTimeout,
		sessionLifetime: make(map[uint64]struct{}),
		registrations:   make(map[uint64]uint64),
		resetFn:         resetFn,
		stopCh:          make(chan struct{}),
	}
}

// byStreamID is a reset callback that takes the stream ID alone as one that also takes
// the registration, for the constructors whose callers reset by ID; nil stays nil.
func byStreamID(resetFn func(streamID uint64)) func(streamID, registration uint64) {
	if resetFn == nil {
		return nil
	}
	return func(streamID, _ uint64) { resetFn(streamID) }
}

// NewSessionStreamGC is the stream GC a session runs under opts: streams idle for
// opts.StreamIdleTimeout are reset through resetFn, except the IDs below
// StreamGCExemptBelow and the IDs in opts.SessionLifetimeStreams, which live as long
// as the session. The TCP-family and Noise adapters both build their GC here, so the
// two read one rule for which streams outlive their idleness.
func NewSessionStreamGC(opts SessionOptions, resetFn func(streamID uint64)) *StreamGC {
	return NewSessionStreamGCByRegistration(opts, byStreamID(resetFn))
}

// NewSessionStreamGCByRegistration is NewSessionStreamGC for a session that tracks each
// stream under its registration (RegisterAs): resetFn gets the idle stream's ID and the
// registration that tracked it, zero for an ID tracked without one, so the session
// resets the stream that registration names and leaves alone a later stream that took
// the ID after the sweep let the entry go. The Noise adapter builds its GC here: its
// stream exits run outside the session lock that publishes the ID's next stream, so an
// ID alone does not tell an ended stream from its successor.
func NewSessionStreamGCByRegistration(opts SessionOptions, resetFn func(streamID, registration uint64)) *StreamGC {
	g := newStreamGC(opts.StreamIdleTimeout, resetFn)
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

// Register adds a stream to the GC tracker, under no registration.
func (g *StreamGC) Register(streamID uint64) {
	g.RegisterAs(streamID, 0)
}

// RegisterAs adds a stream to the GC tracker under registration, the caller's name for
// this registration of the ID (the Noise adapter passes the stream's
// scheduler.Registration, which no other registration of the session shares). It
// replaces whatever entry the ID had, so an ended stream's later
// UnregisterRegistration leaves the new one tracked. Zero is Register.
func (g *StreamGC) RegisterAs(streamID, registration uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastActivity[streamID] = time.Now()
	if registration == 0 {
		delete(g.registrations, streamID)
		return
	}
	g.registrations[streamID] = registration
}

// Unregister removes a stream from the GC tracker (already closed), whichever
// registration tracks it.
func (g *StreamGC) Unregister(streamID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.lastActivity, streamID)
	delete(g.registrations, streamID)
}

// UnregisterRegistration is Unregister for registration alone: the ID leaves the
// tracker only while that registration tracks it, so the release of a stream whose ID
// another stream has since registered (RegisterAs) leaves the other stream tracked for
// its own idle timeout. A registration the sweep has already let go is a no-op.
func (g *StreamGC) UnregisterRegistration(streamID, registration uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, tracked := g.lastActivity[streamID]; !tracked || g.registrations[streamID] != registration {
		return
	}
	delete(g.lastActivity, streamID)
	delete(g.registrations, streamID)
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
	regs := make([]uint64, len(expired))
	for i, id := range expired {
		regs[i] = g.registrations[id]
		delete(g.lastActivity, id)
		delete(g.registrations, id)
	}
	g.mu.Unlock()

	// Reset expired streams outside the lock
	for i, id := range expired {
		dbgAether.Printf("Stream GC: resetting idle stream %d (timeout %v)", id, g.idleTimeout)
		if g.resetFn != nil {
			g.resetFn(id, regs[i])
		}
	}
}

// TrackedCount returns the number of streams being tracked.
func (g *StreamGC) TrackedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.lastActivity)
}
