/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/pion/stun"
)

// ael08RogueResponder starts a UDP listener on loopback that reads a single
// datagram (the STUN binding request) and replies with whatever the `reply`
// callback returns. It emulates an off-path attacker who has spoofed the STUN
// server's source IP:port and won the race, exercising the AE-L-08 validation
// added to querySTUNServer. Returns the responder's "host:port" address.
func ael08RogueResponder(t *testing.T, reply func(req *stun.Message) *stun.Message) string {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ael08: listen rogue responder: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	go func() {
		buf := make([]byte, 1500)
		n, from, rerr := srv.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		var req stun.Message
		req.Raw = append([]byte(nil), buf[:n]...)
		_ = req.Decode() // best-effort; responder may ignore the request contents
		resp := reply(&req)
		if resp == nil {
			return
		}
		_, _ = srv.WriteToUDP(resp.Raw, from)
	}()

	return srv.LocalAddr().String()
}

func ael08NewClient(t *testing.T, serverAddr string) *STUNClient {
	t.Helper()
	return NewSTUNClient(aether.STUNConfig{
		Enabled:  true,
		Servers:  []string{serverAddr},
		Timeout:  2 * time.Second,
		CacheTTL: time.Minute,
	})
}

func ael08LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestAEL08_RejectsSpoofedTransactionID is the core regression: a forged
// binding-success carrying a fresh (non-matching) transaction ID must be
// rejected. Before the fix querySTUNServer went straight to GetFrom and
// accepted the attacker's 198.51.100.7:4444, poisoning the reflexive cache.
func TestAEL08_RejectsSpoofedTransactionID(t *testing.T) {
	srvAddr := ael08RogueResponder(t, func(req *stun.Message) *stun.Message {
		// stun.TransactionID generates a FRESH random ID, deliberately NOT
		// echoing the request's transaction ID -> this is the spoof.
		return stun.MustBuild(
			stun.TransactionID,
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.ParseIP("198.51.100.7"), Port: 4444},
		)
	})

	c := ael08NewClient(t, srvAddr)
	res, err := c.querySTUNServer(context.Background(), ael08LocalAddr(), srvAddr)
	if err == nil {
		t.Fatalf("ael08: expected rejection of spoofed transaction ID, got result=%+v", res)
	}
	if res != nil {
		t.Fatalf("ael08: expected nil result on rejection, got %+v", res)
	}
	if !strings.Contains(err.Error(), "transaction ID mismatch") {
		t.Fatalf("ael08: expected transaction ID mismatch error, got: %v", err)
	}
}

// TestAEL08_RejectsWrongMessageType verifies the success-class check: a reply
// that echoes the correct transaction ID but carries an error class must be
// rejected as an unexpected response type (checked before the TID compare).
func TestAEL08_RejectsWrongMessageType(t *testing.T) {
	srvAddr := ael08RogueResponder(t, func(req *stun.Message) *stun.Message {
		return stun.MustBuild(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingError,
			&stun.XORMappedAddress{IP: net.ParseIP("198.51.100.7"), Port: 4444},
		)
	})

	c := ael08NewClient(t, srvAddr)
	res, err := c.querySTUNServer(context.Background(), ael08LocalAddr(), srvAddr)
	if err == nil {
		t.Fatalf("ael08: expected rejection of error-class response, got result=%+v", res)
	}
	if res != nil {
		t.Fatalf("ael08: expected nil result on rejection, got %+v", res)
	}
	if !strings.Contains(err.Error(), "unexpected response type") {
		t.Fatalf("ael08: expected unexpected response type error, got: %v", err)
	}
}

// TestAEL08_AcceptsMatchingTransactionID is the positive control: a legitimate
// binding-success that echoes the request's transaction ID is still accepted
// and yields the advertised mapped address. Guards against the fix rejecting
// valid responses.
func TestAEL08_AcceptsMatchingTransactionID(t *testing.T) {
	srvAddr := ael08RogueResponder(t, func(req *stun.Message) *stun.Message {
		// Echo the request's transaction ID (set FIRST so XORMappedAddress
		// XORs against the correct ID), success class, valid mapped address.
		return stun.MustBuild(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.ParseIP("198.51.100.7"), Port: 4444},
		)
	})

	c := ael08NewClient(t, srvAddr)
	res, err := c.querySTUNServer(context.Background(), ael08LocalAddr(), srvAddr)
	if err != nil {
		t.Fatalf("ael08: expected acceptance of matching transaction ID, got err: %v", err)
	}
	if res == nil {
		t.Fatalf("ael08: expected non-nil result on valid response")
	}
	if !res.IP.Equal(net.ParseIP("198.51.100.7")) || res.Port != 4444 {
		t.Fatalf("ael08: expected mapped address 198.51.100.7:4444, got %s:%d", res.IP, res.Port)
	}
}
