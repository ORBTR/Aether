/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package noise

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestGrantRealm_PrologueBindsEachField: the prologue opens with the over-conn
// label, changes with the partition and with the target, keeps the two fields
// apart (no split of the same bytes gives one prologue), and is refused for a
// grant naming no partition or no target.
func TestGrantRealm_PrologueBindsEachField(t *testing.T) {
	a := GrantRealm{Partition: "partition-A", Target: "vl1_agent"}
	p, err := a.Prologue()
	if err != nil {
		t.Fatalf("prologue: %v", err)
	}
	if !bytes.HasPrefix(p, []byte(grantRealmPrologueLabel+"\x00")) {
		t.Fatalf("prologue % x does not open with the label", p)
	}
	if !bytes.Contains(p, []byte("\x00\x06device")) {
		t.Fatalf("prologue % x does not carry the mesh kind device", p)
	}
	same, _ := GrantRealm{Partition: "partition-A", Target: "vl1_agent"}.Prologue()
	if !bytes.Equal(p, same) {
		t.Fatalf("two equal realms gave different prologues")
	}
	for name, other := range map[string]GrantRealm{
		"another target":    {Partition: "partition-A", Target: "vl1_other"},
		"another partition": {Partition: "partition-B", Target: "vl1_agent"},
		"fields swapped":    {Partition: "vl1_agent", Target: "partition-A"},
	} {
		q, err := other.Prologue()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(p, q) {
			t.Fatalf("%s: same prologue as %+v", name, a)
		}
		idA, _ := a.ID()
		idO, _ := other.ID()
		if idA == idO {
			t.Fatalf("%s: same realm id %08x as %+v", name, idA, a)
		}
	}
	split1, _ := GrantRealm{Partition: "ab", Target: "c"}.Prologue()
	split2, _ := GrantRealm{Partition: "a", Target: "bc"}.Prologue()
	if bytes.Equal(split1, split2) {
		t.Fatalf("two splits of the bytes abc give one prologue")
	}
	for name, bad := range map[string]GrantRealm{
		"no partition": {Target: "vl1_agent"},
		"no target":    {Partition: "partition-A"},
		"empty":        {},
	} {
		if _, err := bad.Prologue(); !errors.Is(err, ErrGrantRealmIncomplete) {
			t.Fatalf("%s: err = %v, want ErrGrantRealmIncomplete", name, err)
		}
		if _, err := bad.ID(); !errors.Is(err, ErrGrantRealmIncomplete) {
			t.Fatalf("%s: ID err = %v, want ErrGrantRealmIncomplete", name, err)
		}
	}
	if _, err := (GrantRealm{Partition: strings.Repeat("p", 0x10000), Target: "t"}).Prologue(); err == nil {
		t.Fatalf("a partition past the u16 length was admitted")
	}
}

// grantPair runs one DialOverConn with ticket and dialRealm against an
// AcceptOverConn under cfg over a net.Pipe, closing the dialer's end on a
// failed dial so the accepter returns, and reports both ends.
func grantPair(t *testing.T, cfg AcceptConnConfig, priv, pub, ticket []byte, dialRealm func([]byte) (GrantRealm, error)) (dialed, accepted aether.Connection, dialErr, acceptErr error, dialWrites int) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	counted := &writeCountConn{Conn: clientConn}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		accepted, acceptErr = AcceptOverConn(ctx, cfg, serverConn)
	}()
	dialed, dialErr = DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_alice",
		StaticPriv:       priv,
		StaticPub:        pub,
		Ticket:           ticket,
		GrantRealmFn:     dialRealm,
		HandshakeTimeout: 2 * time.Second,
	}, counted)
	if dialErr != nil {
		_ = clientConn.Close()
	}
	wg.Wait()
	return dialed, accepted, dialErr, acceptErr, counted.count()
}

// TestOverConn_GrantRealmBoundOnBothEnds: with a grant on the dial and a
// signer on the accept, both conns report the grant's realm, which is
// GrantRealm.ID of the partition and target the grant carries.
func TestOverConn_GrantRealmBoundOnBothEnds(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))
	dialed, accepted, dialErr, acceptErr, _ := grantPair(t, cfg, browserPriv, browserPub, ticket, realmFromGrant)
	if dialErr != nil || acceptErr != nil {
		t.Fatalf("dial %v accept %v", dialErr, acceptErr)
	}
	defer dialed.Close()
	defer accepted.Close()
	want, err := GrantRealm{Partition: "partition-A", Target: "vl1_bob"}.ID()
	if err != nil {
		t.Fatalf("realm id: %v", err)
	}
	for name, c := range map[string]aether.Connection{"dialer": dialed, "accepter": accepted} {
		id, bound := realmOn(t, c)
		if !bound || id != want {
			t.Fatalf("%s reports realm %08x, %v; want the grant's %08x, true", name, id, bound, want)
		}
	}
}

// TestOverConn_GrantRealmMismatchFailsBeforeAnyStream: when the two ends
// derive different realms from the grant, the dialer fails on msg2 and writes
// no msg3, the accepter returns no connection, and the grant's nonce is not
// spent: the same grant then opens with matching realms.
func TestOverConn_GrantRealmMismatchFailsBeforeAnyStream(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cache := NewTicketNonceCache(16)
	cfg := bindingAcceptConfig(t, signerPub, cache)
	browserPriv, browserPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))

	otherTarget := func(body []byte) (GrantRealm, error) {
		g, err := realmFromGrant(body)
		g.Target = "vl1_someone_else"
		return g, err
	}
	dialed, accepted, dialErr, acceptErr, writes := grantPair(t, cfg, browserPriv, browserPub, ticket, otherTarget)
	if dialed != nil || accepted != nil {
		t.Fatalf("a connection exists after a realm mismatch (dialed=%v accepted=%v)", dialed != nil, accepted != nil)
	}
	if dialErr == nil || !strings.Contains(dialErr.Error(), "process msg2") {
		t.Fatalf("dial err = %v, want a failure processing msg2", dialErr)
	}
	if acceptErr == nil {
		t.Fatalf("accepter returned no error for a realm mismatch")
	}
	if writes != 1 {
		t.Fatalf("dialer wrote %d frames, want only msg1 (no msg3 after a refused msg2)", writes)
	}
	// The grant was not spent by the mismatched dial.
	if _, accepted, dialErr, acceptErr, _ := grantPair(t, cfg, browserPriv, browserPub, ticket, realmFromGrant); dialErr != nil || acceptErr != nil {
		t.Fatalf("the grant after a mismatched dial: dial %v accept %v", dialErr, acceptErr)
	} else {
		_ = accepted.Close()
	}
}

// TestOverConn_GrantRealmConfigRefusedBeforeAnyByte: a dialer with a ticket
// and no GrantRealmFn, or a GrantRealmFn and no ticket, is refused before it
// writes; a dialer whose reader returns an incomplete realm likewise.
func TestOverConn_GrantRealmConfigRefusedBeforeAnyByte(t *testing.T) {
	priv, pub := newTestKeypair(t)
	ticket := append([]byte(`{"target":"vl1_bob","scope":"partition-A"}`), make([]byte, ed25519.SignatureSize)...)
	for name, tc := range map[string]struct {
		cfg  DialConnConfig
		want error
	}{
		"ticket without a realm reader": {DialConnConfig{LocalNodeID: "vl1_a", StaticPriv: priv, StaticPub: pub, Ticket: ticket}, ErrTicketWithoutGrantRealm},
		"realm reader without a ticket": {DialConnConfig{LocalNodeID: "vl1_a", StaticPriv: priv, StaticPub: pub, GrantRealmFn: realmFromGrant}, nil},
		"reader gives no partition": {DialConnConfig{LocalNodeID: "vl1_a", StaticPriv: priv, StaticPub: pub, Ticket: ticket,
			GrantRealmFn: func([]byte) (GrantRealm, error) { return GrantRealm{Target: "vl1_bob"}, nil }}, ErrGrantRealmIncomplete},
		"ticket shorter than a signature": {DialConnConfig{LocalNodeID: "vl1_a", StaticPriv: priv, StaticPub: pub, Ticket: []byte("short"), GrantRealmFn: realmFromGrant}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			c := &writeCountConn{Conn: nopConn{}}
			conn, err := DialOverConn(context.Background(), tc.cfg, c)
			if err == nil || conn != nil {
				t.Fatalf("DialOverConn admitted the config: %v", conn)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if c.count() != 0 {
				t.Fatalf("%d writes before refusing the config", c.count())
			}
		})
	}
}

// TestOverConn_AccepterRefusesAGrantItReadsNoRealmFrom: an accepter whose
// GrantRealmFn fails on the verified grant, or returns a realm with no target,
// refuses the dial before it writes msg2 and returns no connection, and the
// grant's nonce stays unspent: the same grant opens once the reader works.
func TestOverConn_AccepterRefusesAGrantItReadsNoRealmFrom(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	browserPriv, browserPub := newTestKeypair(t)
	for name, reader := range map[string]func([]byte) (GrantRealm, error){
		"reader fails":           func([]byte) (GrantRealm, error) { return GrantRealm{}, errors.New("no realm here") },
		"reader gives no target": func([]byte) (GrantRealm, error) { return GrantRealm{Partition: "partition-A"}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
			cfg.GrantRealmFn = reader
			ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			counted := &writeCountConn{Conn: serverConn}
			acceptDone := make(chan error, 1)
			go func() {
				c, err := AcceptOverConn(ctx, cfg, counted)
				if c != nil {
					_ = c.Close()
					err = errors.New("accepter returned a connection")
				}
				acceptDone <- err
				_ = serverConn.Close()
			}()
			go func() {
				c, err := DialOverConn(ctx, DialConnConfig{
					LocalNodeID: "vl1_alice", StaticPriv: browserPriv, StaticPub: browserPub,
					Ticket: ticket, GrantRealmFn: realmFromGrant, HandshakeTimeout: 2 * time.Second,
				}, clientConn)
				if err == nil {
					_ = c.Close()
				}
			}()
			if err := <-acceptDone; err == nil || !strings.Contains(err.Error(), "grant realm") {
				t.Fatalf("accept err = %v, want a refusal naming the grant realm", err)
			}
			if n := counted.count(); n != 0 {
				t.Fatalf("accepter wrote %d frame(s) before refusing the grant it read no realm from", n)
			}
			cfg.GrantRealmFn = realmFromGrant
			if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); err != nil {
				t.Fatalf("the grant after a refused read: %v", err)
			}
		})
	}
}
