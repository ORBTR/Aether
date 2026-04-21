/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"time"
)

// TransportConfig tunes VL1 transport behaviour.
type TransportConfig struct {
	DialTimeout       time.Duration
	HandshakeTimeout  time.Duration
	KeepAliveInterval time.Duration
	SuspectTimeout    time.Duration
	DeadTimeout       time.Duration
	MaxPathCount      int
	STUN              STUNConfig // STUN NAT detection configuration
}

// DefaultTransportConfig reflects the timings from the design document.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		DialTimeout:       5 * time.Second,
		HandshakeTimeout:  3 * time.Second,
		KeepAliveInterval: 5 * time.Second,
		SuspectTimeout:    10 * time.Second,
		DeadTimeout:       20 * time.Second,
		MaxPathCount:      3,
		STUN:              DefaultSTUNConfig(),
	}
}

// SessionConfig specifies Noise/crypto level configuration.
type SessionConfig struct {
	Prologue           []byte
	RekeyAfterBytes    uint64
	RekeyAfterDuration time.Duration
	// InboxSize is the capacity of the per-session inbox channel (decrypted
	// packets awaiting application read). 0 = use DefaultInboxSize.
	// Increase for high-throughput applications; decrease for memory-constrained
	// clients. Overflow is tracked via noiseConn.InboxDrops().
	InboxSize int
}

// DefaultInboxSize is the default capacity of the per-session inbox channel.
const DefaultInboxSize = 128

// MinInboxSize / MaxInboxSize bound SuggestedInboxSize so a wildly
// out-of-spec BDP estimate can't produce a pathological inbox.
const (
	MinInboxSize = 32
	MaxInboxSize = 2048
)

// SuggestedInboxSize returns a BDP-scaled inbox capacity in messages.
// Rationale: the inbox needs to absorb bandwidth-delay-product worth of
// frames between application reads. For a given RTT and peak
// inbound bandwidth (bytes/sec), BDP ≈ RTT × bw bytes; dividing by a
// typical message size gives message count.
//
//	bytesInFlight := int64(rtt.Seconds() * float64(peakBps))
//	msgs := bytesInFlight / int64(avgMsgBytes)
//
// Callers without reliable bandwidth data should pass peakBps=0; we
// fall back to DefaultInboxSize. The result is clamped to
// [MinInboxSize, MaxInboxSize] so it's always safe to use.
//
// avgMsgBytes == 0 is treated as 1400 (typical MSS).
func SuggestedInboxSize(rtt time.Duration, peakBps int64, avgMsgBytes int) int {
	if rtt <= 0 || peakBps <= 0 {
		return DefaultInboxSize
	}
	if avgMsgBytes <= 0 {
		avgMsgBytes = 1400
	}
	bdpBytes := int64(rtt.Seconds() * float64(peakBps))
	msgs := int(bdpBytes / int64(avgMsgBytes))
	if msgs < MinInboxSize {
		msgs = MinInboxSize
	}
	if msgs > MaxInboxSize {
		msgs = MaxInboxSize
	}
	return msgs
}

// DefaultSessionConfig returns conservative defaults for Noise XX/XK sessions.
// The prologue "vl1/noise-xk" is retained for wire compatibility.
// Actual pattern selection (XX vs XK) is determined at dial time by the peer key cache.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		Prologue:           []byte("vl1/noise-xk"),
		RekeyAfterBytes:    1 << 30, // 1 GiB
		RekeyAfterDuration: 10 * time.Minute,
		InboxSize:          DefaultInboxSize,
	}
}
