//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
)

func realmOn(t *testing.T, c aether.Connection) (uint32, bool) {
	t.Helper()
	nc, err := extractNoiseConn(c)
	if err != nil {
		t.Fatalf("extractNoiseConn: %v", err)
	}
	return nc.RealmID()
}

// TestNoiseConn_ReportsTheRealmItsHandshakeBound: the dialed and the accepted
// conn of one mesh-transport handshake both report the fingerprint of the
// network key the Noise prologue bound, which is the realm the fragment
// envelope names on such a session.
func TestNoiseConn_ReportsTheRealmItsHandshakeBound(t *testing.T) {
	p := newWVPair(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accepted := make(chan aether.Connection, 1)
	go func() {
		s, err := p.serverLn.Accept(ctx)
		if err == nil {
			accepted <- s
		}
		close(accepted)
	}()
	c, err := p.client.Dial(ctx, aether.Target{Address: p.serverAddr, NodeID: p.server.localNode})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("c.Close: %v", err)
		}
	}()
	s, ok := <-accepted
	if !ok {
		t.Fatalf("server accepted nothing")
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	}()
	want := transportCrypto.CRC32Hash([]byte(wvTestNetKey))
	for name, conn := range map[string]aether.Connection{"dialer": c, "accepter": s} {
		id, bound := realmOn(t, conn)
		if !bound || id != want {
			t.Fatalf("%s conn network key = %08x, %v; want %08x, true", name, id, bound, want)
		}
	}
}

// TestOverConn_WithoutGrantBindsNoRealm: a conn from DialOverConn or
// AcceptOverConn with no grant runs Noise with an empty prologue, so it reports
// no realm; TestOverConn_GrantRealmBoundOnBothEnds is the arm with a grant.
func TestOverConn_WithoutGrantBindsNoRealm(t *testing.T) {
	dialed, accepted, dialErr, acceptErr := overConnPair(t, nil, nil)
	if dialErr != nil || acceptErr != nil {
		t.Fatalf("over-conn pair: dial %v accept %v", dialErr, acceptErr)
	}
	defer func() {
		if err := dialed.Close(); err != nil {
			t.Errorf("dialed.Close: %v", err)
		}
	}()
	defer func() {
		if err := accepted.Close(); err != nil {
			t.Errorf("accepted.Close: %v", err)
		}
	}()
	for name, conn := range map[string]aether.Connection{"dialer": dialed, "accepter": accepted} {
		if id, bound := realmOn(t, conn); bound {
			t.Fatalf("%s over-conn without a grant reports realm %08x", name, id)
		}
	}
}

// TestTicket_CarriesRealm: the realm a session bound survives a ticket and its
// resume material, an unbound session's ticket stays unbound, and a ticket or
// material cut inside the realm field is refused.
func TestTicket_CarriesRealm(t *testing.T) {
	ts, err := NewTicketStore()
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	offer, _ := aether.LocalWireVersions(nil)
	chosen := mustChoose(t, offer, offer)
	for _, key := range []realmBinding{{id: 0x8badf00d, bound: true}, {}} {
		send, recv := cipherPair(t)
		blob, err := ts.IssueTicket("vl1_peer", send, recv, 0, "", offer, chosen, key)
		if err != nil {
			t.Fatalf("IssueTicket: %v", err)
		}
		tk, err := ts.DecryptTicket(blob)
		if err != nil {
			t.Fatalf("DecryptTicket: %v", err)
		}
		if tk.Realm != key {
			t.Fatalf("ticket realm %+v, want %+v", tk.Realm, key)
		}
		m := &resumeMaterial{Opaque: blob, PeerOffer: offer, Chosen: chosen, ExpiresAt: time.Now().Add(time.Hour), Realm: key}
		enc := encodeResumeMaterial(m)
		back, err := decodeResumeMaterial(enc)
		if err != nil || back.Realm != key {
			t.Fatalf("material round trip: %+v, %v; want key %+v", back, err, key)
		}
		for cut := 1; cut <= realmBindingSize; cut++ {
			if _, err := decodeResumeMaterial(enc[:len(enc)-cut]); err == nil {
				t.Fatalf("material cut by %d decoded", cut)
			}
		}
	}
	if _, err := decodeResumeMaterial(append(encodeResumeMaterial(&resumeMaterial{Realm: realmBinding{id: 1, bound: true}}), 0)); err == nil {
		t.Fatalf("material with a byte past the key decoded")
	}
	bad := encodeRealmBinding(realmBinding{id: 7, bound: true})
	bad[0] = 2
	if _, err := decodeRealmBinding(bad); err == nil {
		t.Fatalf("a bound byte of 2 decoded")
	}
	if _, err := decodeRealmBinding([]byte{0, 0, 0, 0, 1}); err == nil {
		t.Fatalf("an unbound binding with a non-zero id decoded")
	}
}

// TestResume_InitiatorResumedConnBindsTheMaterialsRealm: an initiator that
// resumes from its cached material reports the realm the material recorded,
// which the responder's resumed conn reports from the ticket.
func TestResume_InitiatorResumedConnBindsTheMaterialsRealm(t *testing.T) {
	offer, _ := aether.LocalWireVersions(nil)
	recorded := mustChoose(t, offer, offer)
	key := realmBinding{id: 0x0ddba11, bound: true}
	resp := wvTransport(t, nil, func(c *NoiseTransportConfig) { c.EnableResume = true })
	ini := wvTransport(t, nil, func(c *NoiseTransportConfig) { c.EnableResume = true })
	send, recv := cipherPair(t)
	opaque, err := resp.ticketStore.IssueTicket(ini.localNode, send, recv, capExplicitNonce, "", offer, recorded, key)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	ini.initiatorTickets.Store(resp.localNode, &resumeMaterial{
		Opaque:    opaque,
		SendKey:   recv.UnsafeKey(),
		RecvKey:   send.UnsafeKey(),
		ExpiresAt: time.Now().Add(time.Hour),
		PeerOffer: offer,
		Chosen:    recorded,
		Realm:     key,
	})
	respSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := respSock.Close(); err != nil {
			t.Errorf("respSock.Close: %v", err)
		}
	}()
	iniSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		// A socket closed already (net.ErrClosed) is the end this test wants.
		if err := iniSock.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("iniSock.Close: %v", err)
		}
	}()
	l := &noiseListener{
		transport: resp,
		conn:      respSock,
		sessions:  aether.NewConnectionMap(),
		incoming:  make(chan aether.IncomingSession, 1),
	}
	go func() {
		buf := make([]byte, 1024)
		_ = respSock.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := respSock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		l.handleResumePacket(context.Background(), respSock, buf[:n], src)
	}()
	nc, err := ini.tryResumeDial(context.Background(), aether.Target{NodeID: resp.localNode}, iniSock, respSock.LocalAddr().(*net.UDPAddr))
	if err != nil || nc == nil {
		t.Fatalf("resume: conn %v, %v", nc != nil, err)
	}
	defer func() {
		if err := nc.Close(); err != nil {
			t.Errorf("nc.Close: %v", err)
		}
	}()
	if id, bound := nc.RealmID(); !bound || id != key.id {
		t.Fatalf("resumed initiator conn reports realm %08x, %v; want %08x", id, bound, key.id)
	}
	select {
	case in := <-l.incoming:
		defer func() {
			if err := in.Session.Close(); err != nil {
				t.Errorf("in.Session.Close: %v", err)
			}
		}()
		if id, bound := realmOn(t, in.Session); !bound || id != key.id {
			t.Fatalf("resumed responder conn reports realm %08x, %v; want %08x", id, bound, key.id)
		}
	case <-time.After(time.Second):
		t.Fatalf("the responder delivered no resumed session")
	}
}
