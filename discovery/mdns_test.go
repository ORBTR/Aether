//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package discovery

import (
	"fmt"
	"testing"
	"time"
)

// TestProcessMDNSResponseBoundsDiscoveredMap verifies the AE-M-09 fix: an
// on-LAN attacker minting unlimited distinct nodeIDs (each reaching the
// trust-on-first-use store branch) must not grow d.discovered without bound.
func TestProcessMDNSResponseBoundsDiscoveredMap(t *testing.T) {
	// nil pubkey lookup exercises the unverified store path; nil transport is
	// fine because we call processMDNSResponse directly.
	d := NewMDNSDiscoverer("self", []string{"1.2.3.4:9000"}, 9000, nil, nil)

	for i := 0; i < mdnsMaxDiscovered+500; i++ {
		d.processMDNSResponse(fmt.Sprintf("attacker-%d", i), []string{"10.0.0.1:1"}, "", "")
	}

	d.mu.RLock()
	got := len(d.discovered)
	d.mu.RUnlock()

	if got > mdnsMaxDiscovered {
		t.Fatalf("discovered map grew unbounded: len=%d, want <= %d", got, mdnsMaxDiscovered)
	}
}

// TestProcessMDNSResponsePrunesExpired verifies that a peer not re-announced
// within mdnsPeerTTL is pruned when a new nodeID is inserted (TTL prune via
// DiscoveredAt).
func TestProcessMDNSResponsePrunesExpired(t *testing.T) {
	d := NewMDNSDiscoverer("self", []string{"1.2.3.4:9000"}, 9000, nil, nil)

	// Insert a peer, then age it well past the TTL.
	d.processMDNSResponse("stale", []string{"10.0.0.2:1"}, "", "")

	d.mu.Lock()
	p := d.discovered["stale"]
	p.DiscoveredAt = time.Now().Add(-2 * mdnsPeerTTL)
	d.discovered["stale"] = p
	d.mu.Unlock()

	// A fresh new-key insertion triggers the prune path.
	d.processMDNSResponse("fresh", []string{"10.0.0.3:1"}, "", "")

	d.mu.RLock()
	_, ok := d.discovered["stale"]
	d.mu.RUnlock()

	if ok {
		t.Fatalf("expected stale peer to be pruned after TTL expiry, but it is still present")
	}
}
