/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"net"
	"testing"
)

// TestIsTrustedNoAmplifySource is the guard for the same-org noise-UDP fix.
//
// The anti-amplification RETRY cookie strands same-org UDP dials: it is bound to
// the responder PROCESS's secret + source IP, so for a multi-machine app the
// msg1+cookie retransmit can land on a different machine that rejects the cookie
// → msg2 timeout (measured: 104 RETRY tokens/75s, dials never establish). A Fly
// 6PN source (IPv6 ULA, fdaa:…) cannot be spoofed across the private network, so
// the amplification the cookie defends against is impossible there — skip it.
//
// A public/global source must STILL get the RETRY (real spoofing exposure).
func TestIsTrustedNoAmplifySource(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"fly-6pn-ula", "fdaa:4d:ce3c:a7b:2d8:f741:87ff:2", true},
		{"generic-ipv6-ula", "fd00::1", true},
		{"public-ipv6", "2606:4700:4700::1111", false},
		{"public-ipv4", "1.1.1.1", false},
		{"rfc1918-ipv4-not-6pn", "10.0.0.1", false}, // v4 private is NOT the 6PN; must still RETRY
		{"loopback-ipv6", "::1", false},             // not ULA
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := &net.UDPAddr{IP: net.ParseIP(c.ip), Port: 41641}
			if got := isTrustedNoAmplifySource(addr); got != c.want {
				t.Fatalf("isTrustedNoAmplifySource(%s) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
	// nil safety.
	if isTrustedNoAmplifySource(nil) {
		t.Fatal("nil addr must not be trusted")
	}
	if isTrustedNoAmplifySource(&net.UDPAddr{}) {
		t.Fatal("addr with nil IP must not be trusted")
	}
}
