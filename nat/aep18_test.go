/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// aep18NewClient builds a minimal single-server STUNClient. detectNATType is
// pure address comparison and touches no client/network state, so the config
// only needs to construct without error.
func aep18NewClient(t *testing.T) *STUNClient {
	t.Helper()
	return NewSTUNClient(aether.STUNConfig{
		Enabled:  true,
		Servers:  []string{"127.0.0.1:3478"},
		Timeout:  time.Second,
		CacheTTL: time.Minute,
	})
}

// TestAEP18_DifferentIPYieldsUnknownNotFullCone is the core regression. A single
// STUN query that observes a reflexive IP differing from the local IP proves
// only that some NAT exists — it cannot tell full-cone from restricted /
// port-restricted / symmetric. Before AE-P-18 detectNATType fabricated a
// confident aether.NATFullCone here, a frequently-wrong classification that
// leaked to external peers via ReflexiveAddress.NATType. It must now report
// aether.NATUnknown so callers fall through to the multi-server detection path.
func TestAEP18_DifferentIPYieldsUnknownNotFullCone(t *testing.T) {
	c := aep18NewClient(t)
	local := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 51000}
	public := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}

	got := c.detectNATType(local, public)
	if got == aether.NATFullCone {
		t.Fatalf("aep18: single-server detection must not fabricate NATFullCone for a mapped IP that differs from local")
	}
	if got != aether.NATUnknown {
		t.Fatalf("aep18: expected NATUnknown for undetermined NAT, got %v", got)
	}
}

// TestAEP18_SameIPStillOpen is the positive control for the no-NAT branch: a
// reflexive IP equal to the local IP is genuine evidence of a direct/open path
// and must keep reporting aether.NATOpen (unchanged by the fix).
func TestAEP18_SameIPStillOpen(t *testing.T) {
	c := aep18NewClient(t)
	local := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 51000}
	public := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 40000}

	if got := c.detectNATType(local, public); got != aether.NATOpen {
		t.Fatalf("aep18: expected NATOpen when public IP matches local IP, got %v", got)
	}
}

// TestAEP18_NilAddrsUnknown guards the nil-input branch: with no observable
// mapping there is nothing to classify, so the result stays aether.NATUnknown.
func TestAEP18_NilAddrsUnknown(t *testing.T) {
	c := aep18NewClient(t)
	if got := c.detectNATType(nil, nil); got != aether.NATUnknown {
		t.Fatalf("aep18: expected NATUnknown for nil addresses, got %v", got)
	}
	local := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 51000}
	if got := c.detectNATType(local, nil); got != aether.NATUnknown {
		t.Fatalf("aep18: expected NATUnknown when public addr is nil, got %v", got)
	}
}
