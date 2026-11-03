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

	"github.com/ORBTR/aether"
	"github.com/flynn/noise"
)

// overConnPair runs DialOverConn and AcceptOverConn against each other over
// a net.Pipe with the given application entries, closing the dialer's end
// when the dial fails so a waiting accepter returns.
func overConnPair(t *testing.T, dialApp, acceptApp aether.WireVersions) (dialed, accepted aether.Connection, dialErr, acceptErr error) {
	t.Helper()
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		accepted, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:      "vl1_bob-test",
			StaticPriv:       bPriv,
			StaticPub:        bPub,
			HandshakeTimeout: 2 * time.Second,
			WireVersions:     acceptApp,
		}, serverConn)
	}()
	dialed, dialErr = DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_alice-test",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		HandshakeTimeout: 2 * time.Second,
		WireVersions:     dialApp,
	}, clientConn)
	if dialErr != nil {
		_ = clientConn.Close()
	}
	<-done
	return dialed, accepted, dialErr, acceptErr
}

func chosenOn(t *testing.T, c aether.Connection) aether.NegotiatedWireVersions {
	t.Helper()
	nc, err := extractNoiseConn(c)
	if err != nil {
		t.Fatalf("extractNoiseConn: %v", err)
	}
	return nc.WireVersions()
}

// TestOverConn_IncompatibleWireVersionsRefuse: a required application entry
// with no common version refuses the dial with ErrWireVersionMismatch before
// msg3, so neither side returns a connection.
func TestOverConn_IncompatibleWireVersionsRefuse(t *testing.T) {
	dialed, accepted, dialErr, acceptErr := overConnPair(t,
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2}, Required: true}})
	if !errors.Is(dialErr, aether.ErrWireVersionMismatch) {
		t.Fatalf("dial err = %v, want ErrWireVersionMismatch", dialErr)
	}
	if dialed != nil || accepted != nil {
		t.Fatalf("a connection exists after a refused handshake (dialed=%v accepted=%v)", dialed != nil, accepted != nil)
	}
	if acceptErr == nil {
		t.Fatalf("accepter returned no error for a refused handshake")
	}
}

// TestOverConn_CompatibleWireVersionsChosenOnBothEnds: both ends report the
// same chosen set, the highest common version of every listed name.
func TestOverConn_CompatibleWireVersionsChosenOnBothEnds(t *testing.T) {
	dialed, accepted, dialErr, acceptErr := overConnPair(t,
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2, 3}, Required: true}})
	if dialErr != nil || acceptErr != nil {
		t.Fatalf("dial=%v accept=%v", dialErr, acceptErr)
	}
	defer dialed.Close()
	defer accepted.Close()
	a, b := chosenOn(t, dialed), chosenOn(t, accepted)
	if !a.Equal(b) {
		t.Fatalf("ends disagree: dialer %v accepter %v", a, b)
	}
	for name, want := range map[string]uint16{"frame": aether.WireVersionFrameCurrent, "frame.short": 1, "gossip.codec": 2, "reliability": 1} {
		if v, ok := a.Version(name); !ok || v != want {
			t.Fatalf("%s = %d, %v; want %d", name, v, ok, want)
		}
	}
}

// TestOverConn_RefusesMalformedLocalEntries: an application entry that names
// one of aether's entries is refused before anything is written.
func TestOverConn_RefusesMalformedLocalEntries(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	c := &writeCountConn{Conn: nopConn{}}
	_, err := DialOverConn(context.Background(), DialConnConfig{
		LocalNodeID:  "vl1_alice-test",
		StaticPriv:   aPriv,
		StaticPub:    aPub,
		WireVersions: aether.WireVersions{{Name: "frame", Versions: []uint16{9}, Required: true}},
	}, c)
	if !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("err = %v, want ErrWireVersionsMalformed", err)
	}
	if c.count() != 0 {
		t.Fatalf("%d writes before refusing a malformed local offer", c.count())
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) Read([]byte) (int, error)         { return 0, errors.New("nopConn: no reads") }
func (nopConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// handDialer drives the initiator side of the over-conn handshake by hand so
// a test can send a msg3 payload no DialOverConn would write.
func handDialer(t *testing.T, conn net.Conn, msg3Payload func(staticPub []byte) []byte) {
	t.Helper()
	priv, pub := newTestKeypair(t)
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		StaticKeypair: noise.DHKey{Private: priv, Public: pub},
	})
	if err != nil {
		t.Errorf("hand dialer: %v", err)
		return
	}
	msg1, _, _, _ := hs.WriteMessage(nil, nil)
	if err := WriteTicketAndFrame(conn, nil, msg1); err != nil {
		return
	}
	msg2, err := readFrame(conn)
	if err != nil {
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return
	}
	msg3, _, _, _ := hs.WriteMessage(nil, msg3Payload(pub))
	_ = writeFrame(conn, msg3)
}

// TestAcceptOverConn_RefusesDialerOffers: the accepter chooses from the
// dialer's msg3 offer and refuses, returning no connection, when that offer
// is absent (the payload ends at the reserved byte), malformed, or shares no
// version of a required entry.
func TestAcceptOverConn_RefusesDialerOffers(t *testing.T) {
	cases := map[string]struct {
		payload func(pub []byte) []byte
		want    error
	}{
		"no versions field": {
			payload: func(pub []byte) []byte {
				p := []byte{byte(len("vl1_hand"))}
				p = append(p, "vl1_hand"...)
				p = append(p, pub...)
				return append(p, minimalNodeInfoReservedByte)
			},
			want: aether.ErrWireVersionsMalformed,
		},
		"malformed versions": {
			payload: func(pub []byte) []byte {
				p, _ := encodeMinimalNodeInfo("vl1_hand", pub, nil)
				p = p[:len(p)-2]
				return append(p, 0x00, 0x01, 0x07)
			},
			want: aether.ErrWireVersionsMalformed,
		},
		"trailing byte after versions": {
			payload: func(pub []byte) []byte {
				local, _ := aether.LocalWireVersions(nil)
				p, _ := encodeMinimalNodeInfo("vl1_hand", pub, local)
				return append(p, 0x00)
			},
			want: aether.ErrWireVersionsMalformed,
		},
		"required entry with no common version": {
			payload: func(pub []byte) []byte {
				p, _ := encodeMinimalNodeInfo("vl1_hand", pub, aether.WireVersions{
					{Name: "frame", Versions: []uint16{1}, Required: true},
				})
				return p
			},
			want: aether.ErrWireVersionMismatch,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			bPriv, bPub := newTestKeypair(t)
			go handDialer(t, clientConn, tc.payload)
			c, err := AcceptOverConn(context.Background(), AcceptConnConfig{
				LocalNodeID:      "vl1_bob-test",
				StaticPriv:       bPriv,
				StaticPub:        bPub,
				HandshakeTimeout: 2 * time.Second,
			}, serverConn)
			if c != nil {
				_ = c.Close()
				t.Fatalf("accepter returned a connection")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDialOverConn_RefusesAccepterWithoutVersions: the dialer chooses from
// the accepter's msg2 offer and refuses, writing no msg3, when the accepter's
// payload carries no versions field.
func TestDialOverConn_RefusesAccepterWithoutVersions(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	msg3Seen := make(chan bool, 1)
	go func() {
		bPriv, bPub := newTestKeypair(t)
		hs, err := noise.NewHandshakeState(noise.Config{
			Pattern:       noise.HandshakeXX,
			CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			StaticKeypair: noise.DHKey{Private: bPriv, Public: bPub},
		})
		if err != nil {
			return
		}
		_, msg1, err := ReadTicketAndFrame(serverConn)
		if err != nil {
			return
		}
		if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
			return
		}
		p := []byte{byte(len("vl1_hand"))}
		p = append(p, "vl1_hand"...)
		p = append(p, bPub...)
		p = append(p, minimalNodeInfoReservedByte)
		msg2, _, _, _ := hs.WriteMessage(nil, p)
		_ = writeFrame(serverConn, msg2)
		_ = serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = readFrame(serverConn)
		msg3Seen <- err == nil
	}()
	aPriv, aPub := newTestKeypair(t)
	c, err := DialOverConn(context.Background(), DialConnConfig{
		LocalNodeID:      "vl1_alice-test",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	if c != nil {
		_ = c.Close()
		t.Fatalf("dialer returned a connection")
	}
	if !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("err = %v, want ErrWireVersionsMalformed", err)
	}
	if <-msg3Seen {
		t.Fatalf("dialer wrote msg3 after refusing the accepter's payload")
	}
}

// grantDialerWithoutChoice drives DialOverConn's handshake by hand under the
// grant ticket and the static key (priv, pub), with the dialer's own wire
// version choice left out: it writes msg3 whatever the accepter offered, as a
// peer of another build or a hostile one would, and reports whether msg3 was
// written. Every other message is DialOverConn's (the grant realm prologue through
// realmFromGrant, the ticket beside msg1, the minimal NodeInfo in msg3), so the
// accepter's own choice is the only thing between this dialer and a conn.
func grantDialerWithoutChoice(t *testing.T, conn net.Conn, priv, pub, ticket []byte, app aether.WireVersions) (wroteMsg3 bool, err error) {
	t.Helper()
	offer, err := aether.LocalWireVersions(app)
	if err != nil {
		return false, err
	}
	prologue, _, err := grantRealmPrologue(realmFromGrant, ticket[:len(ticket)-64])
	if err != nil {
		return false, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      prologue,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		StaticKeypair: noise.DHKey{Private: priv, Public: pub},
	})
	if err != nil {
		return false, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return false, err
	}
	if err := WriteTicketAndFrame(conn, ticket, msg1); err != nil {
		return false, err
	}
	msg2, err := readFrame(conn)
	if err != nil {
		return false, err
	}
	payload, _, _, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return false, err
	}
	if _, _, err := decodeMinimalNodeInfo(payload); err != nil {
		return false, err
	}
	mine, err := encodeMinimalNodeInfo("vl1_alice", pub, offer)
	if err != nil {
		return false, err
	}
	msg3, _, _, err := hs.WriteMessage(nil, mine)
	if err != nil {
		return false, err
	}
	if err := writeFrame(conn, msg3); err != nil {
		return false, err
	}
	return true, nil
}

// acceptInBackground runs AcceptOverConn under cfg on conn and returns the
// channel its result arrives on.
func acceptInBackground(cfg AcceptConnConfig, conn net.Conn) <-chan struct {
	conn aether.Connection
	err  error
} {
	out := make(chan struct {
		conn aether.Connection
		err  error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := AcceptOverConn(ctx, cfg, conn)
		out <- struct {
			conn aether.Connection
			err  error
		}{c, err}
	}()
	return out
}

// TestAcceptOverConn_RefusesADialerThatSkippedItsChoiceAndSpendsNoNonce: a
// dialer under the grant's own key that makes no choice of its own and writes
// msg3 offering a required entry the accepter lacks is refused by the
// accepter's ChooseWireVersions with the typed mismatch naming that entry,
// after msg3 and before any connection, and the grant's nonce is not spent on
// it: a conforming dialer then opens on the same grant, both ends bound to the
// grant's realm, after which the grant is spent and a further dial is refused
// on the nonce before any handshake crypto. This is the accepter's half of the
// over-conn refusal; the dialer's half is
// TestDialOverConn_RefusesBeforeMsg3AndSpendsNoNonce.
func TestAcceptOverConn_RefusesADialerThatSkippedItsChoiceAndSpendsNoNonce(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))

	// 1. The dialer that skipped its choice writes msg3 anyway.
	clientConn, serverConn := net.Pipe()
	accepted := acceptInBackground(cfg, serverConn)
	wrote, derr := grantDialerWithoutChoice(t, clientConn, browserPriv, browserPub, ticket,
		aether.WireVersions{{Name: "zz.dialer-only", Versions: []uint16{1}, Required: true}})
	if !wrote || derr != nil {
		t.Fatalf("the dialer did not reach msg3: wrote=%v err=%v", wrote, derr)
	}
	res := <-accepted
	_ = clientConn.Close()
	_ = serverConn.Close()
	if res.conn != nil {
		_ = res.conn.Close()
		t.Fatalf("the accepter built a connection for a dialer whose offer requires an entry it lacks")
	}
	var mm *aether.WireVersionMismatchError
	if !errors.Is(res.err, aether.ErrWireVersionMismatch) || !errors.As(res.err, &mm) || mm.Name != "zz.dialer-only" {
		t.Fatalf("accept err = %v, want the mismatch naming zz.dialer-only", res.err)
	}

	// 2. The nonce is unspent: a conforming dialer opens on the same grant and
	// both ends report the grant's realm.
	clientConn, serverConn = net.Pipe()
	accepted = acceptInBackground(cfg, serverConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed, derr := DialOverConn(ctx, DialConnConfig{
		LocalNodeID: "vl1_alice", StaticPriv: browserPriv, StaticPub: browserPub,
		Ticket: ticket, GrantRealmFn: realmFromGrant, HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	res = <-accepted
	if derr != nil || res.err != nil || dialed == nil || res.conn == nil {
		t.Fatalf("the grant after the refusal: dial %v accept %v", derr, res.err)
	}
	want, _ := GrantRealm{Partition: "partition-A", Target: "vl1_bob"}.ID()
	for name, c := range map[string]aether.Connection{"dialer": dialed, "accepter": res.conn} {
		if got, bound := realmOn(t, c); !bound || got != want {
			t.Fatalf("%s realm %08x %v, want the grant's %08x bound", name, got, bound, want)
		}
	}
	_ = dialed.Close()
	_ = res.conn.Close()

	// 3. The nonce is spent: the grant is refused before any handshake crypto.
	if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); !errors.Is(err, ErrTicketNonceReplayed) {
		t.Fatalf("the grant after its admitted use: err = %v, want ErrTicketNonceReplayed", err)
	}
}

// TestDialOverConn_RefusesBeforeMsg3AndSpendsNoNonce: a dialer requiring an
// entry the accepter lacks refuses after msg2 with the typed mismatch and
// writes nothing after msg1, so the accepter's read of msg3 ends with the
// dialer's close and builds no connection; the grant's nonce is unspent, so the
// same grant then opens between a conforming pair.
func TestDialOverConn_RefusesBeforeMsg3AndSpendsNoNonce(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))

	clientConn, serverConn := net.Pipe()
	counted := &writeCountConn{Conn: clientConn}
	accepted := acceptInBackground(cfg, serverConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed, derr := DialOverConn(ctx, DialConnConfig{
		LocalNodeID: "vl1_alice", StaticPriv: browserPriv, StaticPub: browserPub,
		Ticket: ticket, GrantRealmFn: realmFromGrant, HandshakeTimeout: 2 * time.Second,
		WireVersions: aether.WireVersions{{Name: "zz.dialer-only", Versions: []uint16{1}, Required: true}},
	}, counted)
	if dialed != nil {
		_ = dialed.Close()
		t.Fatalf("a dialer requiring an entry the accepter lacks built a connection")
	}
	var mm *aether.WireVersionMismatchError
	if !errors.Is(derr, aether.ErrWireVersionMismatch) || !errors.As(derr, &mm) || mm.Name != "zz.dialer-only" {
		t.Fatalf("dial err = %v, want the mismatch naming zz.dialer-only", derr)
	}
	if n := counted.count(); n != 1 {
		t.Fatalf("the dialer wrote %d frames, want only msg1", n)
	}
	_ = clientConn.Close()
	res := <-accepted
	_ = serverConn.Close()
	if res.conn != nil {
		_ = res.conn.Close()
		t.Fatalf("the accepter built a connection for a dialer that refused at msg2")
	}
	if res.err == nil {
		t.Fatalf("the accepter returned no error for a dialer that sent no msg3")
	}

	// The nonce is unspent: the grant opens between a conforming pair.
	if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); err != nil {
		t.Fatalf("the grant after the dialer's refusal: %v", err)
	}
}
