//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package pmtu implements Path MTU discovery for Aether over UDP transports.
// Sends PATH_PROBE frames with increasing payload sizes to discover the
// maximum frame size a path can carry without fragmentation.
package pmtu

import (
	"log"
	"sync"
	"time"
)

const (
	// DefaultMSS is the default maximum segment size (conservative for UDP).
	DefaultMSS = 1400

	// MinMSS is the minimum MSS we'll accept.
	MinMSS = 576

	// MaxMSS is the maximum MSS to probe for.
	MaxMSS = 9000 // jumbo frames

	// ProbeInterval is how often to re-probe (PMTU can change).
	ProbeInterval = 10 * time.Minute

	// ProbeTimeout is how long to wait for a probe response.
	ProbeTimeout = 5 * time.Second
)

// ProbeState tracks the PMTU probing state machine.
type ProbeState int

const (
	ProbeIdle     ProbeState = iota // not probing
	ProbeActive                     // sending probes with increasing sizes
	ProbeComplete                   // PMTU discovered
)

// Prober discovers the Path MTU for a connection.
type Prober struct {
	mu sync.Mutex

	// Current PMTU estimate
	mss int

	// Probing state
	state      ProbeState
	probeID    uint32
	probeSizes []int // sizes to try (ascending)
	probeIndex int   // current index in probeSizes
	probeSent  time.Time
	lastProbe  time.Time

	// Callback to send a PATH_PROBE frame
	sendProbe func(probeID uint32, paddingSize uint16) error
}

// NewProber creates a PMTU prober with a callback for sending probes.
func NewProber(sendProbe func(probeID uint32, paddingSize uint16) error) *Prober {
	return &Prober{
		mss:        DefaultMSS,
		state:      ProbeIdle,
		probeSizes: []int{1400, 1500, 2000, 4000, 8000},
		sendProbe:  sendProbe,
	}
}

// MSS returns the current path MTU estimate.
func (p *Prober) MSS() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mss
}

// StartProbe begins PMTU discovery by sending probes with increasing sizes.
func (p *Prober) StartProbe() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state == ProbeActive {
		return // already probing
	}

	p.state = ProbeActive
	p.probeIndex = 0
	p.probeID++
	p.sendNextProbe()
}

// OnProbeResponse handles a PATH_PROBE response (echoed ProbeID).
// If the response matches our probe, the path supports that size.
func (p *Prober) OnProbeResponse(probeID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != ProbeActive || probeID != p.probeID {
		return // not our probe
	}

	// This size worked — try next
	if p.probeIndex < len(p.probeSizes) {
		p.mss = p.probeSizes[p.probeIndex]
		dbgPMTU.Printf("Probe %d succeeded: MSS=%d", probeID, p.mss)
	}

	p.probeIndex++
	if p.probeIndex >= len(p.probeSizes) {
		// All probes done
		p.state = ProbeComplete
		p.lastProbe = time.Now()
		dbgPMTU.Printf("Discovery complete: MSS=%d", p.mss)
		return
	}

	// Send next probe
	p.probeID++
	p.sendNextProbe()
}

// OnProbeTimeout handles no response to a probe.
// The previous successful size is the PMTU.
func (p *Prober) OnProbeTimeout() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != ProbeActive {
		return
	}

	// Current size failed — PMTU is the last successful size
	p.state = ProbeComplete
	p.lastProbe = time.Now()
	dbgPMTU.Printf("Probe timed out at size %d: MSS=%d (using last successful)",
		p.probeSizes[p.probeIndex], p.mss)
}

// IsProbing returns true if a probe is currently in-flight.
func (p *Prober) IsProbing() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state == ProbeActive
}

// ProbeTimedOut returns true if the current probe has exceeded ProbeTimeout.
func (p *Prober) ProbeTimedOut() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state == ProbeActive && !p.probeSent.IsZero() && time.Since(p.probeSent) > ProbeTimeout
}

// ShouldReprobe returns true if it's time to re-probe (PMTU can change).
func (p *Prober) ShouldReprobe() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state == ProbeComplete && time.Since(p.lastProbe) > ProbeInterval
}

// sendNextProbe sends the next probe in the sequence. Must hold mu.
func (p *Prober) sendNextProbe() {
	if p.probeIndex >= len(p.probeSizes) {
		return
	}
	size := p.probeSizes[p.probeIndex]
	paddingSize := uint16(size - 50) // subtract header
	if paddingSize > 65535 {
		paddingSize = 65535
	}

	p.probeSent = time.Now()
	if p.sendProbe != nil {
		if err := p.sendProbe(p.probeID, paddingSize); err != nil {
			log.Printf("[PMTU] Failed to send probe %d (size %d): %v", p.probeID, size, err)
		}
	}
}
