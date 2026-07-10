//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * RekeyTracker manages cipher state ratcheting thresholds. Extracted from
 * noiseConn to be a composable unit reusable by any encrypted session.
 */
package noise

import (
	"sync/atomic"
	"time"
)

// RekeyTracker manages byte and time thresholds for cipher state ratcheting.
// Thread-safe via atomic operations.
type RekeyTracker struct {
	bytesSent   atomic.Uint64
	lastTime    atomic.Int64  // Unix nanos of last rekey (or session start)
	totalRekeys atomic.Uint64 // OBS-15: lifetime count of completed send-side rekeys
	threshBytes uint64        // 0 = disabled
	threshDur   time.Duration // 0 = disabled
}

// NewRekeyTracker creates a tracker with the given thresholds.
func NewRekeyTracker(threshBytes uint64, threshDur time.Duration) *RekeyTracker {
	rt := &RekeyTracker{
		threshBytes: threshBytes,
		threshDur:   threshDur,
	}
	rt.lastTime.Store(time.Now().UnixNano())
	return rt
}

// AddBytesSent records bytes encrypted for threshold tracking.
func (rt *RekeyTracker) AddBytesSent(n uint64) {
	rt.bytesSent.Add(n)
}

// ShouldRekey returns true if byte or time threshold is exceeded.
func (rt *RekeyTracker) ShouldRekey() bool {
	if rt.threshBytes == 0 && rt.threshDur == 0 {
		return false
	}
	byteThresh := rt.threshBytes > 0 && rt.bytesSent.Load() >= rt.threshBytes
	timeThresh := rt.threshDur > 0 && time.Since(time.Unix(0, rt.lastTime.Load())) >= rt.threshDur
	return byteThresh || timeThresh
}

// ResetSend resets counters after a send-side rekey. Bumps the lifetime
// totalRekeys counter (OBS-15) so Library AggregateAetherStats can report
// how often each session has ratcheted its send cipher — the raw signal
// for sustained-throughput sessions hitting the byte threshold or
// long-lived idle sessions hitting the time threshold.
func (rt *RekeyTracker) ResetSend() {
	rt.bytesSent.Store(0)
	rt.lastTime.Store(time.Now().UnixNano())
	rt.totalRekeys.Add(1)
}

// ResetRecv is a no-op — Noise protocol rekey is send-side only.
// The receive side automatically accepts new keys from the remote's rekey message.
// No counter reset needed on receive because we only track send bytes/time.
func (rt *RekeyTracker) ResetRecv() {}

// BytesSent returns the current send byte count since last rekey.
func (rt *RekeyTracker) BytesSent() uint64 {
	return rt.bytesSent.Load()
}

// TimeSinceRekey returns duration since last rekey.
func (rt *RekeyTracker) TimeSinceRekey() time.Duration {
	return time.Since(time.Unix(0, rt.lastTime.Load()))
}

// ThreshBytes returns the byte threshold.
func (rt *RekeyTracker) ThreshBytes() uint64 {
	return rt.threshBytes
}

// ThreshDur returns the time threshold.
func (rt *RekeyTracker) ThreshDur() time.Duration {
	return rt.threshDur
}

// TotalRekeys returns the lifetime count of send-side rekeys completed
// (OBS-15). Each successful ResetSend bumps this exactly once. Surfaced
// up the stack as SessionMetrics.RekeyTotal so Library MeshMetrics can
// aggregate fleet-wide. Atomic load — safe to sample outside any lock.
func (rt *RekeyTracker) TotalRekeys() uint64 {
	return rt.totalRekeys.Load()
}
