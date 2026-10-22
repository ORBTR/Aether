//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	"github.com/flynn/noise"
)

const wvTestNetKey = "wire-versions-test-network-key"

func wvTransport(t *testing.T, app aether.WireVersions, mutate func(*NoiseTransportConfig)) *NoiseTransport {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	id, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	cfg := NoiseTransportConfig{
		PrivateKey:        priv,
		LocalNode:         id,
		ListenAddr:        "127.0.0.1:0",
		NetworkKeys:       []string{wvTestNetKey},
		RequireRetryToken: BoolPtr(false),
		WireVersions:      app,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	tr, err := NewNoiseTransport(cfg)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return tr
}

type wvPair struct {
	server, client     *NoiseTransport
	serverLn, clientLn aether.Listener
	serverAddr         string
}

func newWVPair(t *testing.T, serverApp, clientApp aether.WireVersions) *wvPair {
	t.Helper()
	p := &wvPair{server: wvTransport(t, serverApp, nil), client: wvTransport(t, clientApp, nil)}
	ctx := context.Background()
	var err error
	if p.serverLn, err = p.server.Listen(ctx); err != nil {
		t.Fatalf("server listen: %v", err)
	}
	if p.clientLn, err = p.client.Listen(ctx); err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { _ = p.serverLn.Close(); _ = p.clientLn.Close() })
	p.serverAddr = p.serverLn.Addr().String()
	time.Sleep(30 * time.Millisecond)
	return p
}

// TestNoiseHandshake_IncompatibleWireVersionsRefuseBeforeSession: with a
// required application entry that has no common version, the dial returns
// ErrWireVersionMismatch and neither transport holds a session for the peer.
func TestNoiseHandshake_IncompatibleWireVersionsRefuseBeforeSession(t *testing.T) {
	p := newWVPair(t,
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2}, Required: true}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := p.client.Dial(ctx, aether.Target{Address: p.serverAddr, NodeID: p.server.localNode})
	if !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("dial err = %v, want ErrWireVersionMismatch", err)
	}
	if c != nil {
		t.Fatalf("dial returned a connection")
	}
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer acceptCancel()
	if s, err := p.serverLn.Accept(acceptCtx); err == nil {
		t.Fatalf("server accepted a session %v after a refused handshake", s.RemoteNodeID())
	}
	if p.server.listener.sessions.Get(p.client.localNode) != nil {
		t.Fatalf("server holds a session for the refused client")
	}
	if p.client.listener.sessions.Get(p.server.localNode) != nil {
		t.Fatalf("client holds a session for the refused server")
	}
}

// TestNoiseHandshake_CompatibleWireVersionsChosenOnBothEnds: the dialed and
// the accepted connection report the same chosen set.
func TestNoiseHandshake_CompatibleWireVersionsChosenOnBothEnds(t *testing.T) {
	p := newWVPair(t,
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2, 3}, Required: true}})
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
	defer c.Close()
	s, ok := <-accepted
	if !ok {
		t.Fatalf("server accepted nothing")
	}
	defer s.Close()
	a, b := chosenOn(t, c), chosenOn(t, s)
	if !a.Equal(b) {
		t.Fatalf("ends disagree: dialer %v accepter %v", a, b)
	}
	if v, ok := a.Version("gossip.codec"); !ok || v != 2 {
		t.Fatalf("gossip.codec = %d, %v; want 2", v, ok)
	}
	if v, ok := a.Version(aether.WireVersionFrame); !ok || v != 2 {
		t.Fatalf("frame = %d, %v; want 2", v, ok)
	}
}

// TestNewNoiseTransport_RefusesMalformedEntries: an application entry that
// names an aether entry is refused at construction.
func TestNewNoiseTransport_RefusesMalformedEntries(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:   priv,
		NetworkKeys:  []string{wvTestNetKey},
		WireVersions: aether.WireVersions{{Name: "frame.short", Versions: []uint16{1}}},
	})
	if !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("err = %v, want ErrWireVersionsMalformed", err)
	}
}

// handInitiator drives the initiator side of the UDP handshake by hand,
// inside the dial-nonce envelope the listener routes on, so a test controls
// the NodeInfo payload of msg3.
type handInitiator struct {
	t     *testing.T
	conn  *net.UDPConn
	id    *transportCrypto.Identity
	nonce []byte
}

func newHandInitiator(t *testing.T) *handInitiator {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	id, err := transportCrypto.NewIdentity(priv)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	nonce := make([]byte, dialNonceLen)
	_, _ = rand.Read(nonce)
	return &handInitiator{t: t, conn: conn, id: id, nonce: nonce}
}

func (h *handInitiator) envelope(b []byte) []byte {
	out := []byte{dialNoncePrefix}
	out = append(out, h.nonce...)
	return append(out, b...)
}

// run completes a handshake with dst, sending payload3 as msg3's NodeInfo.
func (h *handInitiator) run(dst *net.UDPAddr, payload3 []byte) error {
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      []byte(wvTestNetKey),
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		StaticKeypair: noise.DHKey{Private: h.id.Curve25519Priv, Public: h.id.Curve25519Pub},
		Random:        rand.Reader,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	pkt := make([]byte, 5, 5+len(msg1))
	binary.BigEndian.PutUint32(pkt, transportCrypto.CRC32Hash([]byte(wvTestNetKey)))
	pkt[4] = patternFlagXX
	pkt = append(pkt, msg1...)
	if _, err := h.conn.WriteToUDP(h.envelope(pkt), dst); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	_ = h.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := h.conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	resp := buf[:n]
	if len(resp) > 1+dialNonceLen && resp[0] == dialNoncePrefix {
		resp = resp[1+dialNonceLen:]
	}
	if _, _, _, err := hs.ReadMessage(nil, resp); err != nil {
		return err
	}
	msg3, _, _, err := hs.WriteMessage(nil, payload3)
	if err != nil {
		return err
	}
	_, err = h.conn.WriteToUDP(h.envelope(msg3), dst)
	return err
}

// nodeInfoWithout encodes a valid signed NodeInfo for id and removes the
// named JSON fields, so a test can send a NodeInfo some field is absent from.
func nodeInfoWithout(t *testing.T, id *transportCrypto.Identity, offer aether.WireVersions, drop ...string) []byte {
	t.Helper()
	b, err := id.EncodeNodeInfo(capExplicitNonce, 0, offer)
	if err != nil {
		t.Fatalf("EncodeNodeInfo: %v", err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	for _, k := range drop {
		delete(m, k)
	}
	out, _ := json.Marshal(m)
	return out
}

// TestNoiseResponder_RefusesNodeInfoWithoutVersions: a msg3 whose NodeInfo
// carries no versions field completes no session at the responder, while the
// same hand-built initiator with this build's offer does: the control arm
// shows the refusal is the field, not the harness.
func TestNoiseResponder_RefusesNodeInfoWithoutVersions(t *testing.T) {
	local, _ := aether.LocalWireVersions(nil)
	for _, tc := range []struct {
		name    string
		drop    []string
		accepts bool
	}{
		{name: "with versions", accepts: true},
		{name: "without versions", drop: []string{"versions"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := wvTransport(t, nil, nil)
			ln, err := resp.Listen(context.Background())
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			h := newHandInitiator(t)
			dst := ln.Addr().(*net.UDPAddr)
			if err := h.run(dst, nodeInfoWithout(t, h.id, local, tc.drop...)); err != nil {
				t.Fatalf("hand initiator: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			s, err := ln.Accept(ctx)
			if tc.accepts {
				if err != nil {
					t.Fatalf("control arm accepted nothing: %v", err)
				}
				if got := chosenOn(t, s); !got.Equal(mustChoose(t, local, local)) {
					t.Fatalf("control arm chose %v", got)
				}
				_ = s.Close()
				return
			}
			if err == nil {
				t.Fatalf("responder accepted a session from a NodeInfo without versions")
			}
			if resp.listener.sessions.Get(h.id.NodeID) != nil {
				t.Fatalf("responder registered a session for the refused initiator")
			}
			if got := resp.listener.DropSnapshot()[DropWireVersionMismatch.String()]; got == 0 {
				t.Fatalf("refusal not counted under %s", DropWireVersionMismatch)
			}
		})
	}
}

func mustChoose(t *testing.T, a, b aether.WireVersions) aether.NegotiatedWireVersions {
	t.Helper()
	n, err := aether.ChooseWireVersions(a, b)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	return n
}

// TestNoiseInitiator_RefusesResponderWithoutVersions: when msg2's NodeInfo
// carries no versions field the dial returns ErrWireVersionMismatch and no
// msg3 leaves the initiator.
func TestNoiseInitiator_RefusesResponderWithoutVersions(t *testing.T) {
	respID := func() *transportCrypto.Identity {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := transportCrypto.NewIdentity(priv)
		return id
	}()
	shim, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("shim: %v", err)
	}
	defer shim.Close()
	var afterMsg2 int64
	go func() {
		buf := make([]byte, 4096)
		answered := false
		for {
			n, src, err := shim.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := buf[:n]
			if len(pkt) < 1+dialNonceLen || pkt[0] != dialNoncePrefix {
				continue
			}
			nonce := append([]byte(nil), pkt[1:1+dialNonceLen]...)
			inner := pkt[1+dialNonceLen:]
			if answered {
				if len(inner) != 5+32 { // anything but a msg1 retransmit is msg3
					atomic.AddInt64(&afterMsg2, 1)
				}
				continue
			}
			hs, err := noise.NewHandshakeState(noise.Config{
				Pattern:       noise.HandshakeXX,
				Prologue:      []byte(wvTestNetKey),
				CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
				StaticKeypair: noise.DHKey{Private: respID.Curve25519Priv, Public: respID.Curve25519Pub},
				Random:        rand.Reader,
			})
			if err != nil || len(inner) < 5 {
				continue
			}
			if _, _, _, err := hs.ReadMessage(nil, inner[5:]); err != nil {
				continue
			}
			msg2, _, _, err := hs.WriteMessage(nil, nodeInfoWithout(t, respID, nil, "versions"))
			if err != nil {
				continue
			}
			_, _ = shim.WriteToUDP(wrapDialResponse(nonce, msg2), src)
			answered = true
		}
	}()

	cli := wvTransport(t, nil, nil)
	ln, err := cli.Listen(context.Background())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := cli.Dial(ctx, aether.Target{Address: shim.LocalAddr().String(), NodeID: respID.NodeID})
	if c != nil {
		_ = c.Close()
	}
	if !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("dial err = %v, want ErrWireVersionMismatch", err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt64(&afterMsg2); got != 0 {
		t.Fatalf("initiator sent %d packets after a msg2 it refused", got)
	}
}

func cipherPair(t *testing.T) (*noise.CipherState, *noise.CipherState) {
	t.Helper()
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	var k1, k2 [32]byte
	_, _ = rand.Read(k1[:])
	_, _ = rand.Read(k2[:])
	return noise.UnsafeNewCipherState(cs, k1, 0), noise.UnsafeNewCipherState(cs, k2, 0)
}

// resumePacketFor builds the 0xFA packet an initiator holding the ticket's
// keys sends (initiator send = responder recv).
func resumePacketFor(t *testing.T, opaque []byte, respSend, respRecv [32]byte) []byte {
	t.Helper()
	eph, err := newResumeEphemeral()
	if err != nil {
		t.Fatalf("ephemeral: %v", err)
	}
	ephPub := eph.PublicKey().Bytes()
	psk := canonicalResumePSK(respRecv, respSend)
	binder := resumeBinder(psk, opaque, ephPub)
	pkt := []byte{resumePrefix}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(opaque)))
	pkt = append(pkt, opaque...)
	pkt = append(pkt, ephPub...)
	return append(pkt, binder...)
}

// TestResume_ResponderRefusesTicketWhoseSetThisBuildWouldNotChoose: a ticket
// records the peer's offer and the chosen set. The responder accepts the
// resume only when choosing again from its own offer and the recorded peer
// offer gives the recorded set; otherwise it rejects, which sends the
// initiator to a full handshake. The accepted resume reports the recorded set.
func TestResume_ResponderRefusesTicketWhoseSetThisBuildWouldNotChoose(t *testing.T) {
	peerOffer, _ := aether.LocalWireVersions(aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}})
	for _, tc := range []struct {
		name    string
		respApp aether.WireVersions
		accept  bool
	}{
		{name: "same build", respApp: aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}}, accept: true},
		{name: "responder now chooses another version", respApp: aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}}},
		{name: "responder now refuses the peer offer", respApp: aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{3}, Required: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := wvTransport(t, tc.respApp, func(c *NoiseTransportConfig) { c.EnableResume = true })
			// The ticket was issued by a build whose offer chose gossip.codec=2.
			recorded := mustChoose(t, peerOffer, peerOffer)
			send, recv := cipherPair(t)
			peer := aether.NodeID("vl1_resume_peer")
			opaque, err := resp.ticketStore.IssueTicket(peer, send, recv, capExplicitNonce, "", peerOffer, recorded, realmBinding{id: 0xfeedbeef, bound: true})
			if err != nil {
				t.Fatalf("IssueTicket: %v", err)
			}
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer conn.Close()
			ini, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ini.Close()
			l := &noiseListener{
				transport: resp,
				conn:      conn,
				sessions:  aether.NewConnectionMap(),
				incoming:  make(chan aether.IncomingSession, 1),
			}
			pkt := resumePacketFor(t, opaque, send.UnsafeKey(), recv.UnsafeKey())
			l.handleResumePacket(context.Background(), conn, pkt, ini.LocalAddr().(*net.UDPAddr))
			buf := make([]byte, 256)
			_ = ini.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := ini.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("no reply: %v", err)
			}
			if tc.accept {
				if buf[0] != resumeAcceptPrefix {
					t.Fatalf("reply 0x%02x, want accept", buf[0])
				}
				select {
				case in := <-l.incoming:
					if got := chosenOn(t, in.Session); !got.Equal(recorded) {
						t.Fatalf("resumed session reports %v, want %v", got, recorded)
					}
					if id, bound := realmOn(t, in.Session); !bound || id != 0xfeedbeef {
						t.Fatalf("resumed session reports realm %08x, %v; want the ticket's feedbeef", id, bound)
					}
					_ = in.Session.Close()
				case <-time.After(time.Second):
					t.Fatalf("accepted resume delivered no session")
				}
				return
			}
			if n != 1 || buf[0] != resumeRejectPrefix {
				t.Fatalf("reply %x, want a reject", buf[:n])
			}
			if l.sessions.Get(peer) != nil {
				t.Fatalf("rejected resume registered a session")
			}
		})
	}
}

// TestResume_InitiatorSkipsMaterialWhoseSetThisBuildWouldNotChoose: the
// initiator sends no resume packet, and drops the cached material, when
// choosing from its own offer and the material's recorded peer offer does not
// give the recorded set; Dial then runs the full handshake. With matching
// material the resume packet is sent.
func TestResume_InitiatorSkipsMaterialWhoseSetThisBuildWouldNotChoose(t *testing.T) {
	peerOffer, _ := aether.LocalWireVersions(aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}})
	recorded := mustChoose(t, peerOffer, peerOffer)
	for _, tc := range []struct {
		name  string
		app   aether.WireVersions
		sends bool
	}{
		{name: "same build", app: aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}}, sends: true},
		{name: "initiator now chooses another version", app: aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ini := wvTransport(t, tc.app, func(c *NoiseTransportConfig) { c.EnableResume = true })
			peer := aether.NodeID("vl1_resume_responder")
			var k1, k2 [32]byte
			ini.initiatorTickets.Store(peer, &resumeMaterial{
				Opaque:    make([]byte, ticketNonceSize+ticketTagSize+8),
				SendKey:   k1,
				RecvKey:   k2,
				ExpiresAt: time.Now().Add(time.Hour),
				PeerOffer: peerOffer,
				Chosen:    recorded,
			})
			respSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer respSock.Close()
			iniSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer iniSock.Close()
			got := make(chan byte, 1)
			go func() {
				buf := make([]byte, 512)
				_ = respSock.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
				n, src, err := respSock.ReadFromUDP(buf)
				if err != nil || n == 0 {
					close(got)
					return
				}
				got <- buf[0]
				_, _ = respSock.WriteToUDP([]byte{resumeRejectPrefix}, src)
			}()
			nc, err := ini.tryResumeDial(context.Background(), aether.Target{NodeID: peer}, iniSock, respSock.LocalAddr().(*net.UDPAddr))
			if nc != nil {
				t.Fatalf("resume produced a conn")
			}
			first, sent := <-got
			if tc.sends {
				if !sent || first != resumePrefix {
					t.Fatalf("matching material sent no resume packet (err=%v)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("skipped resume returned %v, want (nil, nil) so Dial runs the full handshake", err)
			}
			if sent {
				t.Fatalf("initiator sent 0x%02x for material whose set it would not choose", first)
			}
			if ini.initiatorTickets.Lookup(peer) != nil {
				t.Fatalf("material whose set this build would not choose stays cached")
			}
		})
	}
}

// TestTicket_CarriesWireVersions: a ticket's peer offer and chosen set
// survive encryption, and a ticket whose version suffix is cut short is
// refused.
func TestTicket_CarriesWireVersions(t *testing.T) {
	ts, err := NewTicketStore()
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	offer, _ := aether.LocalWireVersions(aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{4}, Required: true}})
	chosen := mustChoose(t, offer, offer)
	send, recv := cipherPair(t)
	blob, err := ts.IssueTicket("vl1_peer", send, recv, 0, "scope-a", offer, chosen, realmBinding{})
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	tk, err := ts.DecryptTicket(blob)
	if err != nil {
		t.Fatalf("DecryptTicket: %v", err)
	}
	if tk.ScopeID != "scope-a" || !tk.Chosen.Equal(chosen) {
		t.Fatalf("ticket scope %q chosen %v", tk.ScopeID, tk.Chosen)
	}
	if got, _ := tk.PeerOffer.Encode(); string(got) != string(mustEncode(t, offer)) {
		t.Fatalf("peer offer %+v, want %+v", tk.PeerOffer, offer)
	}

	m := &resumeMaterial{Opaque: blob, PeerOffer: offer, Chosen: chosen, ExpiresAt: time.Now().Add(time.Hour)}
	enc := encodeResumeMaterial(m)
	back, err := decodeResumeMaterial(enc)
	if err != nil || !back.Chosen.Equal(chosen) || string(mustEncode(t, back.PeerOffer)) != string(mustEncode(t, offer)) {
		t.Fatalf("material round trip: %+v, %v", back, err)
	}
	if _, err := decodeResumeMaterial(enc[:len(enc)-1]); err == nil {
		t.Fatalf("truncated material decoded")
	}
	if _, err := decodeResumeMaterial(append(enc, 0)); err == nil {
		t.Fatalf("material with a trailing byte decoded")
	}
}

func mustEncode(t *testing.T, w aether.WireVersions) []byte {
	t.Helper()
	b, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}
