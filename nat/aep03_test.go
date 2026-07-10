/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

// aep03Addrs returns a mixed IPv4/IPv6 candidate-address slice for tests.
func aep03Addrs() []net.UDPAddr {
	return []net.UDPAddr{
		{IP: net.ParseIP("203.0.113.7"), Port: 5000},
		{IP: net.ParseIP("2001:db8::1"), Port: 41000},
	}
}

// AE-P-03: signing over candidate addresses. A signed PunchRequest/Offer whose
// address slices are rewritten by a MITM on the rendezvous channel must now fail
// Verify. These tests fail against the pre-fix code (addresses omitted from
// SignBytes) and pass after the fix.

func TestAEP03_RequestSignVerifyWithAddrs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		ReflexiveAddrs:  aep03Addrs(),
		LocalAddrs:      aep03Addrs(),
		Behaviour:       NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent},
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	if err := r.Verify(pub); err != nil {
		t.Fatalf("Verify failed on signed addrs: %v", err)
	}
}

func TestAEP03_OfferSignVerifyWithAddrs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	o := &PunchOffer{
		ResponderNodeID: "vl1_bob",
		RequesterNodeID: "vl1_alice",
		ReflexiveAddrs:  aep03Addrs(),
		LocalAddrs:      aep03Addrs(),
		Behaviour:       NATBehaviour{MappingAddressPortDependent, FilteringAddressPortDependent},
		Method:          PunchPortPrediction,
		Timestamp:       time.Now().Unix(),
	}
	o.Sign(priv)
	if err := o.Verify(pub); err != nil {
		t.Fatalf("Verify failed on signed addrs: %v", err)
	}
}

// Port rewrite on a request LocalAddr must be detected.
func TestAEP03_RequestPortTamperDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		LocalAddrs:      aep03Addrs(),
		Behaviour:       NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent},
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	r.LocalAddrs[0].Port = 6000 // MITM redirect
	if err := r.Verify(pub); err != ErrPunchSignature {
		t.Fatalf("port tamper: got %v, want ErrPunchSignature", err)
	}
}

// IP rewrite on a request LocalAddr (redirect at a victim) must be detected.
func TestAEP03_RequestIPTamperDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		LocalAddrs:      aep03Addrs(),
		Behaviour:       NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent},
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	r.LocalAddrs[0].IP = net.ParseIP("198.51.100.9") // amplification/reflection target
	if err := r.Verify(pub); err != ErrPunchSignature {
		t.Fatalf("ip tamper: got %v, want ErrPunchSignature", err)
	}
}

// Reflexive-address rewrite on the initiator-half (offer) must be detected.
func TestAEP03_OfferReflexiveTamperDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	o := &PunchOffer{
		ResponderNodeID: "vl1_bob",
		RequesterNodeID: "vl1_alice",
		ReflexiveAddrs:  aep03Addrs(),
		Behaviour:       NATBehaviour{MappingAddressPortDependent, FilteringAddressPortDependent},
		Method:          PunchPortPrediction,
		Timestamp:       time.Now().Unix(),
	}
	o.Sign(priv)
	o.ReflexiveAddrs[0].IP = net.ParseIP("198.51.100.9")
	if err := o.Verify(pub); err != ErrPunchSignature {
		t.Fatalf("reflexive tamper: got %v, want ErrPunchSignature", err)
	}
}

// The 4-byte length prefix must defeat splice (append) and truncate (drop).
func TestAEP03_LengthSpliceDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Append an extra candidate after signing.
	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		LocalAddrs:      aep03Addrs(),
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	r.LocalAddrs = append(r.LocalAddrs, net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 7000})
	if err := r.Verify(pub); err != ErrPunchSignature {
		t.Fatalf("splice-append: got %v, want ErrPunchSignature", err)
	}

	// Drop a candidate after signing.
	r2 := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		LocalAddrs:      aep03Addrs(),
		Timestamp:       time.Now().Unix(),
	}
	r2.Sign(priv)
	r2.LocalAddrs = r2.LocalAddrs[:1]
	if err := r2.Verify(pub); err != ErrPunchSignature {
		t.Fatalf("splice-drop: got %v, want ErrPunchSignature", err)
	}
}

// Address-free structs (nil/empty slices) must still round-trip (count prefix 0).
func TestAEP03_EmptyAddrsRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		Behaviour:       NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent},
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	if err := r.Verify(pub); err != nil {
		t.Fatalf("empty-addr request Verify: %v", err)
	}

	o := &PunchOffer{
		ResponderNodeID: "vl1_bob",
		RequesterNodeID: "vl1_alice",
		Method:          PunchDirect,
		Timestamp:       time.Now().Unix(),
	}
	o.Sign(priv)
	if err := o.Verify(pub); err != nil {
		t.Fatalf("empty-addr offer Verify: %v", err)
	}
}
