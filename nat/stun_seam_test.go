//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"net"
	"testing"

	aether "github.com/ORBTR/aether"
	"github.com/pion/stun"
)

// TestSTUNClient_RegisteredForTheSeam: linking this package registers its client,
// so aether.NewSTUNClient, which a Noise transport whose config enables STUN calls,
// builds a *STUNClient from the config it is given.
func TestSTUNClient_RegisteredForTheSeam(t *testing.T) {
	c, err := aether.NewSTUNClient(aether.STUNConfig{Enabled: true, Servers: []string{"stun.example:3478"}})
	if err != nil {
		t.Fatalf("NewSTUNClient with this package linked: %v", err)
	}
	sc, ok := c.(*STUNClient)
	if !ok {
		t.Fatalf("NewSTUNClient built a %T, want *nat.STUNClient", c)
	}
	if got := sc.Config().Servers; len(got) != 1 || got[0] != "stun.example:3478" {
		t.Fatalf("the client's servers: %v", got)
	}
}

// TestSTUNClient_BindingRoundTrip: BindingRequest's bytes are a STUN message under
// the ID it returns; BindingResponse reads a binding success to that ID back as the
// ID and its XOR-MAPPED-ADDRESS, and answers a binding error with the ID and an error.
// The binding error carries an XOR-MAPPED-ADDRESS too, so only BindingResponse's
// check of the message type refuses it.
func TestSTUNClient_BindingRoundTrip(t *testing.T) {
	c := NewSTUNClient(aether.DefaultSTUNConfig())
	id, raw := c.BindingRequest()
	if !aether.IsSTUNMessage(raw) {
		t.Fatal("the binding request is not read as STUN")
	}
	req := &stun.Message{Raw: append([]byte(nil), raw...)}
	if err := req.Decode(); err != nil || req.TransactionID != id || req.Type != stun.BindingRequest {
		t.Fatalf("the request decodes as %v %x (%v), want a binding request under %x", req.Type, req.TransactionID, err, id)
	}

	ip := net.IPv4(203, 0, 113, 7)
	success := stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingSuccess, &stun.XORMappedAddress{IP: ip, Port: 40000})
	gotID, addr, err := c.BindingResponse(success.Raw)
	if err != nil || gotID != id || addr == nil || !addr.IP.Equal(ip) || addr.Port != 40000 {
		t.Fatalf("a binding success reads as %x %+v %v", gotID, addr, err)
	}

	failure := stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingError, &stun.XORMappedAddress{IP: ip, Port: 40000})
	gotID, addr, err = c.BindingResponse(failure.Raw)
	if err == nil || gotID != id || addr != nil {
		t.Fatalf("a binding error reads as %x %+v %v; want its ID and an error", gotID, addr, err)
	}

	if gotID, _, err := c.BindingResponse([]byte("not stun")); err == nil || gotID != ([12]byte{}) {
		t.Fatalf("bytes that do not decode read as %x, %v; want a zero ID and an error", gotID, err)
	}
}
