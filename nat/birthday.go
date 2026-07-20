//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Birthday-paradox port-prediction punching.
//
// Used when both peers have address+port-dependent mapping (symmetric NAT).
// Each side opens N source ports and probes M candidate destination ports
// around the observed reflexive port. With N=256 candidate ports per side
// we expect ~40% collision probability per attempt; with N=512, ~82%.
package nat

import (
	"net"
)

// BirthdayConfig tunes the prediction window.
type BirthdayConfig struct {
	ProbeCount int // outbound source ports to open per side (default 256)
	PortWindow int // ±range from observed reflexive port (default 128)
}

// DefaultBirthdayConfig returns sensible defaults.
func DefaultBirthdayConfig() BirthdayConfig {
	return BirthdayConfig{ProbeCount: 256, PortWindow: 128}
}

// PredictPorts returns the candidate destination port set surrounding
// each observed reflexive port. Used by the punching loop to address
// outbound probes.
func PredictPorts(observed []net.UDPAddr, window int) []net.UDPAddr {
	if window <= 0 {
		window = 128
	}
	out := make([]net.UDPAddr, 0, len(observed)*(2*window+1))
	// AER-037: emit in center-out delta order (0, +1, -1, +2, -2, …) and
	// round-robin across seeds. PunchCandidates caps the result to
	// MaxPunchCandidates AFTER this expansion; the old seed-major, delta
	// -window→+window order meant the cap kept only the FIRST seed's ports
	// 65–128 BELOW its observed port — never the observed port itself, and
	// never any reflexive address when a LAN address preceded it. Center-out
	// + interleaved keeps the observed port of every seed and its nearest
	// neighbours, which is where a symmetric-NAT birthday collision lands.
	for delta := 0; delta <= window; delta++ {
		for _, ref := range observed {
			for _, d := range dedupeDelta(delta) {
				p := ref.Port + d
				if p <= 0 || p >= 65536 {
					continue
				}
				out = append(out, net.UDPAddr{IP: ref.IP, Port: p})
			}
		}
	}
	return out
}

// dedupeDelta yields the signed deltas to probe at radius d: just {0} at the
// center, and {+d, -d} otherwise. Keeps PredictPorts center-out without
// emitting delta 0 twice.
func dedupeDelta(d int) []int {
	if d == 0 {
		return []int{0}
	}
	return []int{d, -d}
}
