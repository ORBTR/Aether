/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	aether "github.com/ORBTR/aether"
)

func newTestIdentity(t *testing.T) *Identity {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	id, err := NewIdentity(priv)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return id
}

// TestNodeInfo_CarriesWireVersions: the offer a handshake side encodes into
// its NodeInfo is the offer VerifyNodeInfo hands back, field for field.
func TestNodeInfo_CarriesWireVersions(t *testing.T) {
	id := newTestIdentity(t)
	offer := aether.WireVersions{
		{Name: "frame", Versions: []uint16{2}, Required: true},
		{Name: "frame.short", Versions: []uint16{1}},
		{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true},
	}
	payload, err := id.EncodeNodeInfo(0, 0, offer)
	if err != nil {
		t.Fatalf("EncodeNodeInfo: %v", err)
	}
	got, err := VerifyNodeInfo(id.Curve25519Pub, payload, id.NodeID)
	if err != nil {
		t.Fatalf("VerifyNodeInfo: %v", err)
	}
	if got.NodeID != id.NodeID {
		t.Fatalf("node id %s, want %s", got.NodeID, id.NodeID)
	}
	if !reflect.DeepEqual(got.WireVersions, offer) {
		t.Fatalf("versions %+v, want %+v", got.WireVersions, offer)
	}
}

// TestNodeInfo_RefusesMalformedWireVersions: a NodeInfo whose versions field
// is not a canonical encoding fails verification, and a NodeInfo that leaves
// the field out verifies to an empty offer, which the handshake's choice then
// refuses on aether's required frame entry.
func TestNodeInfo_RefusesMalformedWireVersions(t *testing.T) {
	id := newTestIdentity(t)
	payload, err := id.EncodeNodeInfo(0, 0, aether.WireVersions{{Name: "frame", Versions: []uint16{2}, Required: true}})
	if err != nil {
		t.Fatalf("EncodeNodeInfo: %v", err)
	}
	var info map[string]interface{}
	if err := json.Unmarshal(payload, &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	info["versions"] = []byte{5, 'f', 'r', 'a', 'm', 'e', 1, 0, 2, 7} // required byte 7
	bad, _ := json.Marshal(info)
	if _, err := VerifyNodeInfo(id.Curve25519Pub, bad, id.NodeID); !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("malformed versions: err = %v, want ErrWireVersionsMalformed", err)
	}

	delete(info, "versions")
	absent, _ := json.Marshal(info)
	got, err := VerifyNodeInfo(id.Curve25519Pub, absent, id.NodeID)
	if err != nil {
		t.Fatalf("absent versions: %v", err)
	}
	if len(got.WireVersions) != 0 {
		t.Fatalf("absent versions verified to %+v, want the empty offer", got.WireVersions)
	}
	local, _ := aether.LocalWireVersions(nil)
	if _, err := aether.ChooseWireVersions(local, got.WireVersions); !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("choice against an absent offer: err = %v, want ErrWireVersionMismatch", err)
	}
}

// TestEncodeNodeInfo_RefusesMalformedOffer: a local offer that is not in
// canonical form never reaches the wire.
func TestEncodeNodeInfo_RefusesMalformedOffer(t *testing.T) {
	id := newTestIdentity(t)
	bad := aether.WireVersions{{Name: "frame", Versions: []uint16{2, 1}, Required: true}}
	if _, err := id.EncodeNodeInfo(0, 0, bad); !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("err = %v, want ErrWireVersionsMalformed", err)
	}
}
