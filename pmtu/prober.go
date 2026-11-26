/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */

// Package pmtu implements Path MTU discovery for Aether over UDP transports.
// Sends PATH_PROBE frames with increasing payload sizes to discover the
// maximum frame size a path can carry without fragmentation.
package pmtu

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMSS is the default maximum segment size (conservative for UDP).
	DefaultMSS = 1400

	// MinMSS is the minimum MSS we'll accept.
	MinMSS = 576

	// SafeFloorMSS is the conservative MSS used as the starting point before
	// PMTU discovery completes, and the low end of the probe sweep. Sized to
	// fit a tunnelled IPv6 path at the 1280-byte minimum MTU (minus IPv6, UDP
	// and Noise overhead), the smallest a private network can run. Data flows at
	// this floor from session start; the prober then probes UPWARD to the real
	// path maximum, so no capacity is lost on paths that support more.
	// Starting at DefaultMSS (1400) instead would strand a sub-1400 path such
	// as that one: the first 1400-byte probe is dropped, OnProbeTimeout keeps
	// the last successful size and there is none, so mss stays 1400 and every
	// data frame is dropped.
	SafeFloorMSS = 1200

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
//
// mu guards the sweep's state and is never held across sendProbe. The sendProbe
// NewNoiseSession passes writes the PATH_PROBE frame through
// NoiseSession.writeFrame, which waits on the session's writeMu and on
// conn.Write, and noiseStream.Send reads MSS for every message under its
// caller's context, so a probe write made under mu would hold every Send on the
// session, and the state reads reliabilityTick makes, for as long as that write
// waits. Each method that sends decides the probe under mu and calls sendProbe
// after releasing it.
type Prober struct {
	mu sync.Mutex

	// mss is the current PMTU estimate. It is stored under mu, beside the sweep
	// state that decides it, and loaded without mu, so MSS waits on nothing.
	mss atomic.Int64

	// Probing state
	state      ProbeState
	probeID    uint32
	probeSizes []int // sizes to try (ascending)
	probeIndex int   // current index in probeSizes
	probeSent  time.Time
	lastProbe  time.Time

	// Callback to send a PATH_PROBE frame
	sendProbe func(probeID uint32, size uint16) error
}

// NewProber creates a PMTU prober with a callback for sending probes. size is the
// MSS the probe tests: the callback sends a frame that long on the wire, so a
// response confirms exactly the MSS OnProbeResponse then sets. What the frame's
// header and seal take from that size is the session's knowledge (NewNoiseSession's
// callback), since this package sees neither.
func NewProber(sendProbe func(probeID uint32, size uint16) error) *Prober {
	p := &Prober{
		state:      ProbeIdle,
		probeSizes: []int{SafeFloorMSS, 1280, 1400, 1500, 2000, 4000, 8000},
		sendProbe:  sendProbe,
	}
	// Start at the safe floor so data flows immediately even on a path under
	// 1400 bytes, such as a 1280-byte IPv6 tunnel; probeSizes then discover the
	// real max upward.
	p.mss.Store(SafeFloorMSS)
	return p
}

// MSS returns the current path MTU estimate. It takes no lock, so it never
// waits on a probe's write.
func (p *Prober) MSS() int {
	return int(p.mss.Load())
}

// StartProbe begins PMTU discovery by sending probes with increasing sizes.
// The first probe's write happens after mu is released.
func (p *Prober) StartProbe() {
	p.beginSweep().send()
}

// beginSweep moves an idle or finished sweep to active and returns its first
// probe for StartProbe to send once mu is released.
func (p *Prober) beginSweep() pendingProbe {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state == ProbeActive {
		return pendingProbe{} // already probing
	}

	p.state = ProbeActive
	p.probeIndex = 0
	p.probeID++
	return p.nextProbeLocked()
}

// OnProbeResponse handles a PATH_PROBE response (echoed ProbeID).
// If the response matches our probe, the path supports that size. The next
// probe's write happens after mu is released.
func (p *Prober) OnProbeResponse(probeID uint32) {
	p.recordResponse(probeID).send()
}

// recordResponse records a matching response's size as the MSS and returns the
// sweep's next probe, if any, for OnProbeResponse to send once mu is released.
func (p *Prober) recordResponse(probeID uint32) pendingProbe {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != ProbeActive || probeID != p.probeID {
		return pendingProbe{} // not our probe
	}

	// This size worked — try next
	if p.probeIndex < len(p.probeSizes) {
		p.mss.Store(int64(p.probeSizes[p.probeIndex]))
		dbgPMTU.Printf("Probe %d succeeded: MSS=%d", probeID, p.mss.Load())
	}

	p.probeIndex++
	if p.probeIndex >= len(p.probeSizes) {
		// All probes done
		p.state = ProbeComplete
		p.lastProbe = time.Now()
		dbgPMTU.Printf("Discovery complete: MSS=%d", p.mss.Load())
		return pendingProbe{}
	}

	// Send next probe
	p.probeID++
	return p.nextProbeLocked()
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
		p.probeSizes[p.probeIndex], p.mss.Load())
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

// pendingProbe is a probe decided under mu and sent after mu is released. The
// zero value sends nothing.
type pendingProbe struct {
	sendProbe func(probeID uint32, size uint16) error
	probeID   uint32
	size      int
}

// nextProbeLocked stamps probeSent for the probe at probeIndex and returns it.
// Caller holds mu. probeSent is stamped before the write, so a write that waits
// past ProbeTimeout reads as a timed-out probe to ProbeTimedOut and the sweep
// ends at the last size answered; a response to that probe's ID that arrives
// after OnProbeTimeout finds the sweep no longer active and changes nothing.
func (p *Prober) nextProbeLocked() pendingProbe {
	if p.probeIndex >= len(p.probeSizes) {
		return pendingProbe{}
	}
	p.probeSent = time.Now()
	return pendingProbe{sendProbe: p.sendProbe, probeID: p.probeID, size: p.probeSizes[p.probeIndex]}
}

// send calls sendProbe for the probe. Callers hold no lock of the Prober's.
func (pp pendingProbe) send() {
	if pp.sendProbe == nil {
		return
	}
	if err := pp.sendProbe(pp.probeID, uint16(pp.size)); err != nil {
		log.Printf("[PMTU] Failed to send probe %d (size %d): %v", pp.probeID, pp.size, err)
	}
}
