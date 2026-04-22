/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	for _, ref := range observed {
		for delta := -window; delta <= window; delta++ {
			p := ref.Port + delta
			if p <= 0 || p >= 65536 {
				continue
			}
			out = append(out, net.UDPAddr{IP: ref.IP, Port: p})
		}
	}
	return out
}
