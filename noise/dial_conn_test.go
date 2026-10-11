/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package noise

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/flynn/noise"
)

// newTestKeypair generates a Curve25519 static keypair for DialOverConn
// tests. Returns (priv, pub). Uses the noise library's DH25519 suite
// directly — same primitive DialOverConn uses internally.
func newTestKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	kp, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return kp.Private, kp.Public
}

// Round-trip: DialOverConn and AcceptOverConn against each other over a
// net.Pipe must complete the handshake and produce sessions that each
// believe the other to be the expected NodeID.
func TestDialAcceptOverConn_RoundTrip(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	aID := aether.NodeID("vl1_alice-test")
	bID := aether.NodeID("vl1_bob-test")

	clientConn, serverConn := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg         sync.WaitGroup
		acceptSess aether.Connection
		acceptErr  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptSess, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:      bID,
			StaticPriv:       bPriv,
			StaticPub:        bPub,
			HandshakeTimeout: 2 * time.Second,
		}, serverConn)
	}()

	dialSess, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      aID,
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	if err != nil {
		t.Fatalf("DialOverConn: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptOverConn: %v", acceptErr)
	}

	if dialSess.RemoteNodeID() != bID {
		t.Errorf("dial side: remote = %s, want %s", dialSess.RemoteNodeID(), bID)
	}
	if acceptSess.RemoteNodeID() != aID {
		t.Errorf("accept side: remote = %s, want %s", acceptSess.RemoteNodeID(), aID)
	}
	_ = dialSess.Close()
	_ = acceptSess.Close()
}

// Ticket carried in the preamble is validated by the responder. A good
// signature passes, a bad signature fails the handshake before any
// Noise state is advanced.
func TestAcceptOverConn_TicketGoodSignatureAccepted(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}

	body := []byte(`{"target":"vl1_agent-xyz","scope":"tenant-42"}`)
	sig := ed25519Sign(signerPriv, body)
	ticket := append(append([]byte(nil), body...), sig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		validated bool
		acceptErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:         "vl1_bob",
			StaticPriv:          bPriv,
			StaticPub:           bPub,
			TrustedTicketSigner: signerPub,
			ValidateTicketFn: func(b []byte) error {
				if string(b) != string(body) {
					return fmt.Errorf("body mismatch")
				}
				validated = true
				return nil
			},
			HandshakeTimeout: 2 * time.Second,
		}, serverConn)
	}()

	if _, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_alice",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		Ticket:           ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn); err != nil {
		t.Fatalf("DialOverConn: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptOverConn: %v", acceptErr)
	}
	if !validated {
		t.Fatal("ValidateTicketFn was not invoked after a good sig")
	}
}

// Bad ticket signature is rejected before the Noise handshake runs.
func TestAcceptOverConn_TicketBadSignatureRejected(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	signerPub, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}

	body := []byte("scope=tenant-42")
	// Sign with a DIFFERENT key — signature won't verify against signerPub.
	_, otherPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	badSig := ed25519Sign(otherPriv, body)
	ticket := append(append([]byte(nil), body...), badSig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var acceptErr error
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:         "vl1_bob",
			StaticPriv:          bPriv,
			StaticPub:           bPub,
			TrustedTicketSigner: signerPub,
			HandshakeTimeout:    2 * time.Second,
		}, serverConn)
	}()

	if _, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_alice",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		Ticket:           ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn); err == nil {
		t.Fatal("DialOverConn succeeded despite bad ticket sig on accept side")
	}
	// AER-030: synchronize with the accept goroutine via a channel before
	// reading acceptErr. The previous 50ms sleep left a data race (write in
	// the goroutine, read here) that the -race detector flagged, making CI
	// flaky.
	<-acceptDone
	if acceptErr == nil {
		t.Error("AcceptOverConn succeeded with bad ticket signature")
	}
}

// A configured TrustedTicketSigner refuses a zero-length ticket: the accept
// does not skip the signature and ValidateTicketFn checks for a dialer that
// sends none. Those two checks are all that binds a dialer on this path, so a
// dialer admitted without them completes the XX handshake under a static key
// it minted itself, which the relay's browser bridge would then pair.
func TestAcceptOverConn_EmptyTicketRejectedWhenSignerConfigured(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	signerPub, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		acceptErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:         "vl1_bob",
			StaticPriv:          bPriv,
			StaticPub:           bPub,
			TrustedTicketSigner: signerPub,
			ValidateTicketFn: func([]byte) error {
				t.Error("ValidateTicketFn must not run for an empty ticket")
				return nil
			},
			HandshakeTimeout: 2 * time.Second,
		}, serverConn)
	}()

	// Initiator presents NO ticket (ticketLen=0). With a signer configured on
	// the accept side this must fail closed before the handshake completes.
	go func() {
		_, _ = DialOverConn(ctx, DialConnConfig{
			LocalNodeID:      "vl1_alice",
			StaticPriv:       aPriv,
			StaticPub:        aPub,
			Ticket:           nil,
			HandshakeTimeout: 2 * time.Second,
		}, clientConn)
	}()

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptOverConn accepted a zero-length ticket with a signer configured (auth bypass)")
	}
}

// grantTicket signs a ticket body carrying the fields the binding hooks
// below read: the initiator key the grant names, a nonce and an expiry.
func grantTicket(t *testing.T, signer ed25519.PrivateKey, browserPub, nonce []byte, exp time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"target":     "vl1_bob",
		"browserPub": hex.EncodeToString(browserPub),
		"nonce":      hex.EncodeToString(nonce),
		"exp":        exp.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	return append(body, ed25519Sign(signer, body)...)
}

// grantFields decodes what grantTicket wrote.
func grantFields(body []byte) (browserPub, nonce []byte, exp time.Time, err error) {
	var g struct {
		BrowserPub string `json:"browserPub"`
		Nonce      string `json:"nonce"`
		Exp        int64  `json:"exp"`
	}
	if err = json.Unmarshal(body, &g); err != nil {
		return nil, nil, time.Time{}, err
	}
	if browserPub, err = hex.DecodeString(g.BrowserPub); err != nil {
		return nil, nil, time.Time{}, err
	}
	if nonce, err = hex.DecodeString(g.Nonce); err != nil {
		return nil, nil, time.Time{}, err
	}
	return browserPub, nonce, time.Unix(g.Exp, 0), nil
}

// bindingAcceptConfig is an accepter that binds the grant to the Noise
// initiator's static key and spends its nonce in cache.
func bindingAcceptConfig(t *testing.T, signerPub ed25519.PublicKey, cache *TicketNonceCache) AcceptConnConfig {
	t.Helper()
	priv, pub := newTestKeypair(t)
	return AcceptConnConfig{
		LocalNodeID:         "vl1_bob",
		StaticPriv:          priv,
		StaticPub:           pub,
		TrustedTicketSigner: signerPub,
		ValidatePeerStaticFn: func(body, peerStatic []byte) error {
			want, _, _, err := grantFields(body)
			if err != nil {
				return err
			}
			if !bytes.Equal(want, peerStatic) {
				return fmt.Errorf("initiator key %x is not the grant's %x", peerStatic, want)
			}
			return nil
		},
		TicketNonces: cache,
		TicketNonceFn: func(body []byte) ([]byte, time.Time, error) {
			_, nonce, exp, err := grantFields(body)
			return nonce, exp, err
		},
		HandshakeTimeout: 2 * time.Second,
	}
}

// acceptWithDialer runs one AcceptOverConn under cfg against a
// DialOverConn presenting ticket under the static key (priv, pub), and
// returns the accept side's error.
func acceptWithDialer(cfg AcceptConnConfig, priv, pub, ticket []byte) error {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	accepted := make(chan error, 1)
	go func() {
		c, err := AcceptOverConn(ctx, cfg, serverConn)
		if c != nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	go func() {
		c, err := DialOverConn(ctx, DialConnConfig{
			LocalNodeID:      "vl1_alice",
			StaticPriv:       priv,
			StaticPub:        pub,
			Ticket:           ticket,
			HandshakeTimeout: 2 * time.Second,
		}, clientConn)
		if err == nil {
			_ = c.Close()
		}
	}()
	return <-accepted
}

// A grant names its initiator's static key. The same signed grant
// presented by a second key completes no handshake, and that refusal does
// not spend the nonce: the key the grant names still opens with it.
func TestAcceptOverConn_GrantFromSecondKeyRefused(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	otherPriv, otherPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))

	err = acceptWithDialer(cfg, otherPriv, otherPub, ticket)
	if err == nil {
		t.Fatal("AcceptOverConn admitted a grant presented by a key the grant does not name")
	}
	if errors.Is(err, ErrTicketNonceReplayed) {
		t.Fatalf("second-key refusal came from the nonce cache, not the key binding: %v", err)
	}
	if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); err != nil {
		t.Fatalf("the grant's own key was refused after a second key tried it: %v", err)
	}
}

// A grant's nonce opens one connection per accepter. Replaying the same
// grant under the same key is refused; a grant with a fresh nonce opens.
func TestAcceptOverConn_ReplayedNonceRefused(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	exp := time.Now().Add(time.Minute)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), exp)

	if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); err != nil {
		t.Fatalf("first use of the grant: %v", err)
	}
	if err := acceptWithDialer(cfg, browserPriv, browserPub, ticket); !errors.Is(err, ErrTicketNonceReplayed) {
		t.Fatalf("replayed grant: err = %v, want ErrTicketNonceReplayed", err)
	}
	fresh := grantTicket(t, signerPriv, browserPub, []byte("nonce-fedcba9876"), exp)
	if err := acceptWithDialer(cfg, browserPriv, browserPub, fresh); err != nil {
		t.Fatalf("grant with a fresh nonce: %v", err)
	}
}

// Each signer's tickets spend nonces in their own space. An accepter that
// trusts two signers through TrustedTicketSignerFn admits one grant from
// each with the same nonce, and still refuses either grant replayed.
func TestAcceptOverConn_NonceSpentPerSigner(t *testing.T) {
	pubA, privA, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer A: %v", err)
	}
	pubB, privB, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer B: %v", err)
	}
	cfg := bindingAcceptConfig(t, nil, NewTicketNonceCache(16))
	cfg.TrustedTicketSigner = nil
	cfg.TrustedTicketSignerFn = func(body []byte) (ed25519.PublicKey, error) {
		var g struct {
			Signer string `json:"signer"`
		}
		if err := json.Unmarshal(body, &g); err != nil {
			return nil, err
		}
		switch g.Signer {
		case "A":
			return pubA, nil
		case "B":
			return pubB, nil
		}
		return nil, fmt.Errorf("unknown signer %q", g.Signer)
	}
	browserPriv, browserPub := newTestKeypair(t)
	exp := time.Now().Add(time.Minute)
	grant := func(signer string, key ed25519.PrivateKey) []byte {
		body, err := json.Marshal(map[string]any{
			"signer":     signer,
			"browserPub": hex.EncodeToString(browserPub),
			"nonce":      hex.EncodeToString([]byte("nonce-shared-0001")),
			"exp":        exp.Unix(),
		})
		if err != nil {
			t.Fatalf("marshal grant: %v", err)
		}
		return append(body, ed25519Sign(key, body)...)
	}
	fromA, fromB := grant("A", privA), grant("B", privB)

	if err := acceptWithDialer(cfg, browserPriv, browserPub, fromA); err != nil {
		t.Fatalf("signer A's grant: %v", err)
	}
	if err := acceptWithDialer(cfg, browserPriv, browserPub, fromB); err != nil {
		t.Fatalf("signer B's grant with the nonce A's grant spent: %v", err)
	}
	for name, g := range map[string][]byte{"A": fromA, "B": fromB} {
		if err := acceptWithDialer(cfg, browserPriv, browserPub, g); !errors.Is(err, ErrTicketNonceReplayed) {
			t.Errorf("signer %s's grant replayed: err = %v, want ErrTicketNonceReplayed", name, err)
		}
	}
}

// writeCountConn is a net.Conn that counts its Writes, so a test can show
// AcceptOverConn refused before sending msg2.
type writeCountConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
}

func (c *writeCountConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *writeCountConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// countingDH is the handshake's key agreement with its calls counted, so a
// test can see whether an accept generated an ephemeral key pair or
// computed a Diffie-Hellman.
type countingDH struct {
	noise.DHFunc
	mu       sync.Mutex
	keyPairs int
	dhs      int
}

func (c *countingDH) GenerateKeypair(random io.Reader) (noise.DHKey, error) {
	c.mu.Lock()
	c.keyPairs++
	c.mu.Unlock()
	return c.DHFunc.GenerateKeypair(random)
}

func (c *countingDH) DH(privkey, pubkey []byte) ([]byte, error) {
	c.mu.Lock()
	c.dhs++
	c.mu.Unlock()
	return c.DHFunc.DH(privkey, pubkey)
}

func (c *countingDH) counts() (keyPairs, dhs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keyPairs, c.dhs
}

// A grant whose nonce the accepter has already spent is refused as soon
// as its ticket is verified: the accepter generates no ephemeral key
// pair, computes no Diffie-Hellman and writes no msg2. The key agreement
// is counted, not inferred from the missing write: the first, admitted
// use of the grant goes through the same counter and shows the one key
// pair and three Diffie-Hellmans a Noise XX responder performs, so the
// zeroes for the replay are zeroes of something that counts.
//
// The refusal is also timed at under a second. The accepter's handshake
// timeout is 2s, which is where a refusal that waited for the dialer's
// next message would land; a passing run refuses within a scheduler
// wake-up of the dialer writing its first message, and the second is room
// for a loaded machine to start the dialer's goroutine.
func TestAcceptOverConn_ReplayedNonceRefusedBeforeHandshake(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	browserPriv, browserPub := newTestKeypair(t)
	ticket := grantTicket(t, signerPriv, browserPub, []byte("nonce-0123456789"), time.Now().Add(time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dh := &countingDH{DHFunc: noise.DH25519}

	// present dials serverConn's other end with the grant and returns what
	// an accept on serverConn, wrapped by wrap, returned.
	present := func(wrap func(net.Conn) net.Conn) error {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		go func() {
			c, err := DialOverConn(ctx, DialConnConfig{
				LocalNodeID:      "vl1_alice",
				StaticPriv:       browserPriv,
				StaticPub:        browserPub,
				Ticket:           ticket,
				HandshakeTimeout: 2 * time.Second,
			}, clientConn)
			if err == nil {
				_ = c.Close()
			}
		}()
		c, err := acceptOverConn(ctx, cfg, wrap(serverConn), dh)
		if c != nil {
			_ = c.Close()
		}
		return err
	}

	if err := present(func(c net.Conn) net.Conn { return c }); err != nil {
		t.Fatalf("first use of the grant: %v", err)
	}
	firstKeyPairs, firstDHs := dh.counts()
	if firstKeyPairs != 1 || firstDHs != 3 {
		t.Fatalf("an admitted accept generated %d key pair(s) and computed %d Diffie-Hellman(s), want 1 and 3", firstKeyPairs, firstDHs)
	}

	var counted *writeCountConn
	start := time.Now()
	err = present(func(c net.Conn) net.Conn {
		counted = &writeCountConn{Conn: c}
		return counted
	})
	waited := time.Since(start)
	if !errors.Is(err, ErrTicketNonceReplayed) {
		t.Fatalf("replayed grant: err = %v, want ErrTicketNonceReplayed", err)
	}
	if keyPairs, dhs := dh.counts(); keyPairs != firstKeyPairs || dhs != firstDHs {
		t.Fatalf("replayed grant: the accepter generated %d key pair(s) and computed %d Diffie-Hellman(s) before refusing it, want 0 and 0",
			keyPairs-firstKeyPairs, dhs-firstDHs)
	}
	if n := counted.count(); n != 0 {
		t.Fatalf("replayed grant: AcceptOverConn wrote %d frame(s) before refusing it", n)
	}
	if waited > time.Second {
		t.Fatalf("replayed grant refused after %v", waited)
	}
}

// unreadConn is a net.Conn whose Read records that it was called and
// fails, so a test can show AcceptOverConn refused before reading.
type unreadConn struct {
	net.Conn
	mu   sync.Mutex
	read bool
}

func (c *unreadConn) Read([]byte) (int, error) {
	c.mu.Lock()
	c.read = true
	c.mu.Unlock()
	return 0, errors.New("unreadConn: Read called")
}

func (c *unreadConn) wasRead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read
}

// The binding hooks act only on a verified ticket, and the nonce cache
// is useless without the reader of the nonce, so each misconfiguration is
// refused, with its own reason, before any byte is read.
func TestAcceptOverConn_TicketBindingConfigRefused(t *testing.T) {
	signerPub, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	base := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))

	noSigner := base
	noSigner.TrustedTicketSigner = nil
	cacheOnly := base
	cacheOnly.TicketNonceFn = nil
	fnOnly := base
	fnOnly.TicketNonces = nil
	for name, tc := range map[string]struct {
		cfg    AcceptConnConfig
		reason string
	}{
		"binding without a signer":   {noSigner, "ticket binding set without a ticket signer"},
		"nonce cache without reader": {cacheOnly, "TicketNonces and TicketNonceFn are set together"},
		"nonce reader without cache": {fnOnly, "TicketNonces and TicketNonceFn are set together"},
	} {
		_, serverConn := net.Pipe()
		conn := &unreadConn{Conn: serverConn}
		start := time.Now()
		_, err := AcceptOverConn(context.Background(), tc.cfg, conn)
		_ = serverConn.Close()
		switch {
		case err == nil:
			t.Errorf("%s: AcceptOverConn accepted the config", name)
		case !strings.Contains(err.Error(), tc.reason):
			t.Errorf("%s: err = %v, want the refusal %q", name, err, tc.reason)
		}
		if conn.wasRead() {
			t.Errorf("%s: AcceptOverConn read from the conn before refusing the config", name)
		}
		if waited := time.Since(start); waited > 500*time.Millisecond {
			t.Errorf("%s: refusal took %v", name, waited)
		}
	}
}

// The cache refuses what it could not guard, keeps every live nonce, and
// admits exactly one of several concurrent uses of one nonce.
func TestTicketNonceCache_Refusals(t *testing.T) {
	live := time.Now().Add(time.Minute)
	signer := ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	c := NewTicketNonceCache(2)
	if err := c.use(signer, nil, live); err == nil {
		t.Error("empty nonce admitted")
	}
	if err := c.use(signer, []byte("n0"), time.Now().Add(-time.Second)); err == nil {
		t.Error("nonce whose ticket already expired admitted")
	}
	if err := c.use(signer, []byte("n1"), live); err != nil {
		t.Fatalf("n1: %v", err)
	}
	if err := c.use(signer, []byte("n2"), live); err != nil {
		t.Fatalf("n2: %v", err)
	}
	if err := c.use(signer, []byte("n3"), live); !errors.Is(err, ErrTicketNonceCacheFull) {
		t.Errorf("cache full of live nonces: err = %v, want ErrTicketNonceCacheFull", err)
	}
	if err := c.use(signer, []byte("n1"), live); !errors.Is(err, ErrTicketNonceReplayed) {
		t.Errorf("live nonce forgotten: err = %v, want ErrTicketNonceReplayed", err)
	}

	race := NewTicketNonceCache(16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if race.use(signer, []byte("shared"), live) == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Errorf("concurrent uses of one nonce admitted %d times, want 1", admitted)
	}
}
