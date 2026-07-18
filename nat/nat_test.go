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

	aether "github.com/ORBTR/aether"
)

func TestLegacyType_Mapping(t *testing.T) {
	cases := []struct {
		b    NATBehaviour
		want aether.NATType
	}{
		{NATBehaviour{MappingEndpointIndependent, FilteringEndpointIndependent}, aether.NATFullCone},
		{NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent}, aether.NATRestricted},
		{NATBehaviour{MappingEndpointIndependent, FilteringAddressPortDependent}, aether.NATPortRestricted},
		{NATBehaviour{MappingAddressDependent, FilteringAddressDependent}, aether.NATSymmetric},
		{NATBehaviour{MappingAddressPortDependent, FilteringAddressPortDependent}, aether.NATSymmetric},
	}
	for _, c := range cases {
		if got := c.b.LegacyType(); got != c.want {
			t.Errorf("%v.LegacyType() = %v, want %v", c.b, got, c.want)
		}
	}
}

func TestChooseMethod(t *testing.T) {
	eim := NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent}
	apdm := NATBehaviour{MappingAddressPortDependent, FilteringAddressPortDependent}

	if m := ChooseMethod(eim, eim); m != PunchDirect {
		t.Errorf("EIM/EIM: got %v, want PunchDirect", m)
	}
	if m := ChooseMethod(apdm, apdm); m != PunchPortPrediction {
		t.Errorf("APDM/APDM: got %v, want PunchPortPrediction", m)
	}
	if m := ChooseMethod(eim, apdm); m != PunchPortPrediction {
		t.Errorf("EIM/APDM: got %v, want PunchPortPrediction (asymmetric punch needs port prediction)", m)
	}
}

func TestPunchRequest_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	r := &PunchRequest{
		RequesterNodeID: "vl1_alice",
		TargetNodeID:    "vl1_bob",
		Behaviour:       NATBehaviour{MappingEndpointIndependent, FilteringAddressDependent},
		Timestamp:       time.Now().Unix(),
	}
	r.Sign(priv)
	if err := r.Verify(pub); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Tampered signature should fail.
	r.RequesterNodeID = "vl1_eve"
	if err := r.Verify(pub); err == nil {
		t.Error("Verify succeeded after tampering")
	}
}

func TestPunchOffer_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	o := &PunchOffer{
		ResponderNodeID: "vl1_bob",
		RequesterNodeID: "vl1_alice",
		Behaviour:       NATBehaviour{MappingAddressPortDependent, FilteringAddressPortDependent},
		Method:          PunchPortPrediction,
		Timestamp:       time.Now().Unix(),
	}
	o.Sign(priv)
	if err := o.Verify(pub); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	o.Method = PunchDirect // mutate after signing
	if err := o.Verify(pub); err == nil {
		t.Error("Verify succeeded after method mutation")
	}
}

func TestPredictPorts(t *testing.T) {
	observed := []net.UDPAddr{{IP: net.ParseIP("203.0.113.1"), Port: 5000}}
	cands := PredictPorts(observed, 2)
	if len(cands) != 5 { // 4998..5002
		t.Fatalf("got %d candidates, want 5", len(cands))
	}
	// AER-037: center-out ordering — the observed port must be emitted FIRST
	// so that PunchCandidates' cap keeps it. The old ascending order emitted
	// the observed port in the middle, so the cap dropped it entirely.
	if cands[0].Port != 5000 {
		t.Errorf("cands[0].Port = %d, want 5000 (observed port first)", cands[0].Port)
	}
	// The full candidate set must still cover the ±window range.
	seen := make(map[int]bool)
	for _, c := range cands {
		seen[c.Port] = true
	}
	for p := 4998; p <= 5002; p++ {
		if !seen[p] {
			t.Errorf("missing candidate port %d", p)
		}
	}
}

func TestNullPortMapper_AlwaysFails(t *testing.T) {
	pm := NullPortMapper{}
	if _, err := pm.Discover(nil); err != ErrNoGateway {
		t.Errorf("Discover: %v, want ErrNoGateway", err)
	}
	if _, err := pm.RequestMapping(nil, MappingRequest{}); err != ErrNoGateway {
		t.Errorf("RequestMapping: %v, want ErrNoGateway", err)
	}
	if err := pm.ReleaseMapping(nil, nil); err != nil {
		t.Errorf("ReleaseMapping: %v, want nil", err)
	}
}
