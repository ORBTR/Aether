//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
	fnoise "github.com/flynn/noise"
)

// realmConn is a net.Conn reporting what a Noise handshake's conn reports: the
// chosen wire version set and the realm the prologue bound.
type realmConn struct {
	net.Conn
	chosen aether.NegotiatedWireVersions
	key    uint32
	bound  bool
}

func (c realmConn) WireVersions() aether.NegotiatedWireVersions { return c.chosen }
func (c realmConn) RealmID() (uint32, bool)                     { return c.key, c.bound }

func aetherChosen(t *testing.T) aether.NegotiatedWireVersions {
	t.Helper()
	chosen, err := aether.ChooseWireVersions(aether.AetherWireVersions(), aether.AetherWireVersions())
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	return chosen
}

// loopbackPair returns the two ends of a loopback TCP connection. Two
// NoiseSessions need a buffered conn between them: each one's readLoop writes
// ACKs, which on an unbuffered net.Pipe wait on the other's blocked readLoop.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s, ok := <-accepted
	if !ok {
		t.Fatalf("accept failed")
	}
	return c, s
}

// noisePairWithRealms runs two NoiseSessions over one loopback connection,
// each conn reporting the realm given for its side.
func noisePairWithRealms(t *testing.T, clientKey, serverKey *uint32) (client, server *NoiseSession) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	wrap := func(conn net.Conn, key *uint32) net.Conn {
		rc := realmConn{Conn: conn, chosen: chosen}
		if key != nil {
			rc.key, rc.bound = *key, true
		}
		return rc
	}
	client = NewNoiseSession(wrap(c, clientKey), "vl1_frag_client", "vl1_frag_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(wrap(s, serverKey), "vl1_frag_server", "vl1_frag_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func openAccept(t *testing.T, ctx context.Context, client, server aether.Session, id uint64) (aether.Stream, aether.Stream) {
	t.Helper()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("hello")); err != nil {
		t.Fatalf("first send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || string(got) != "hello" {
		t.Fatalf("first receive %q, %v", got, err)
	}
	return cs, ss
}

// TestNoiseSession_LargeMessageRoundTripsInFragments: a message many frames
// long arrives as one Receive, byte for byte, and a small message beginning
// with the bytes 'F', 'R', 0, 1 arrives as itself.
func TestNoiseSession_LargeMessageRoundTripsInFragments(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 9)

	msg := make([]byte, 200_000)
	for i := range msg {
		msg[i] = byte(i*31 + 7)
	}
	fr := append([]byte{'F', 'R', 0, 1}, "small payload that starts with FR"...)
	for _, m := range [][]byte{msg, fr, msg} {
		if err := cs.Send(ctx, m); err != nil {
			t.Fatalf("send %d bytes: %v", len(m), err)
		}
		got, err := ss.Receive(ctx)
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if !bytes.Equal(got, m) {
			t.Fatalf("received %d bytes, want the %d sent intact", len(got), len(m))
		}
	}
}

// TestNoiseSession_NoRealmSendsNoFragments: a session whose conn bound no
// network key refuses to split a message, typed, and still sends one that
// fits a frame.
func TestNoiseSession_NoRealmSendsNoFragments(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 9)
	err := cs.Send(ctx, make([]byte, 20_000))
	wantRefusal(t, "a large message on a realmless session", err, FragmentNoRealm)
	if err := cs.Send(ctx, []byte("still")); err != nil {
		t.Fatalf("small send after the refusal: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || string(got) != "still" {
		t.Fatalf("receive %q, %v; want the small message, with no part of the refused one", got, err)
	}
}

// TestNoiseSession_CrossRealmFragmentsNeverJoin: when the two ends' conns bound
// different network keys, the receiver joins none of the sender's fragments,
// and the stream carries on with the next whole message.
func TestNoiseSession_CrossRealmFragmentsNeverJoin(t *testing.T) {
	a, b := uint32(0xaaaa0001), uint32(0xbbbb0002)
	client, server := noisePairWithRealms(t, &a, &b)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 9)
	if err := cs.Send(ctx, make([]byte, 20_000)); err != nil {
		t.Fatalf("large send: %v", err)
	}
	if err := cs.Send(ctx, []byte("next")); err != nil {
		t.Fatalf("small send: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || string(got) != "next" {
		t.Fatalf("receive %d bytes %q, %v; want only the whole message after the refused fragments", len(got), got, err)
	}
	st := ss.(*noiseStream)
	if st.fragBuf.Pending() != 0 || st.fragBuf.BufferedBytes() != 0 {
		t.Fatalf("refused fragments left state: %d groups, %d bytes", st.fragBuf.Pending(), st.fragBuf.BufferedBytes())
	}
	// The sender charged its windows for the refused message, so the receiver
	// grants those bytes back rather than leaving them consumed for good.
	if c := st.window.Stats().Consumed; c < 20_000 {
		t.Fatalf("receiver window consumed %d bytes, want the refused message's 20000 granted back", c)
	}
}

// noiseRawWriter is a peer that writes frames by hand into a NoiseSession whose
// conn bound network key key.
func noiseRawWriter(t *testing.T, key uint32) (*NoiseSession, net.Conn) {
	t.Helper()
	c, peer := net.Pipe()
	sess := NewNoiseSession(realmConn{Conn: c, chosen: aetherChosen(t), key: key, bound: true},
		"vl1_frag_local", "vl1_frag_raw", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = sess.Close(); _ = peer.Close() })
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	return sess, peer
}

func writeFrames(t *testing.T, w io.Writer, frames ...*aether.Frame) {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range frames {
		f.Length = uint32(len(f.Payload))
		if _, err := aether.EncodeFrame(&buf, f); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	go func() { _, _ = w.Write(buf.Bytes()) }()
}

// TestNoiseSession_FrameMarksFragments: an unflagged DATA payload that begins
// with the bytes 'F', 'R', 0, 1 is delivered as it is; a flagged one is a
// fragment and is never delivered as message bytes.
func TestNoiseSession_FrameMarksFragments(t *testing.T) {
	sess, peer := noiseRawWriter(t, 0x1234)
	raw := aether.PeerID{9, 9, 9, 9, 9, 9, 9, 9}
	frBytes := append([]byte{'F', 'R', 0, 1}, "hello"...)
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, InitialCredit: 1 << 20, Generation: 1})
	writeFrames(t, peer,
		&aether.Frame{SenderID: raw, StreamID: 10, Type: aether.TypeOPEN, Payload: openPayload},
		&aether.Frame{SenderID: raw, StreamID: 10, Type: aether.TypeDATA, SeqNo: 0, Payload: frBytes})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := st.Receive(ctx); err != nil || !bytes.Equal(got, frBytes) {
		t.Fatalf("receive %q, %v; want the unflagged payload %q as it is", got, err, frBytes)
	}
	writeFrames(t, peer,
		&aether.Frame{SenderID: raw, StreamID: 10, Type: aether.TypeDATA, Flags: aether.FlagFRAGMENT, SeqNo: 1, Payload: frBytes},
		&aether.Frame{SenderID: raw, StreamID: 10, Type: aether.TypeDATA, SeqNo: 2, Payload: []byte("after")})
	if got, err := st.Receive(ctx); err != nil || string(got) != "after" {
		t.Fatalf("receive %q, %v; want only the message after the refused fragment", got, err)
	}
}

// TestTCPSession_LargeMessageIsOneFrame: a TCPSession has no realm, so a
// message larger than its class frame size goes out as one unflagged DATA
// frame rather than as fragments.
func TestTCPSession_LargeMessageIsOneFrame(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	local, err := aether.ReadWireVersionsPreface(peer)
	if err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(peer, aether.AetherWireVersions()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(aether.AetherWireVersions(), local)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := make([]byte, 200_000)
	go func() {
		st, err := sess.OpenStream(ctx, aether.DefaultStreamConfig(10))
		if err == nil {
			_ = st.Send(ctx, msg)
		}
	}()
	rx := wireDecoder(chosen)
	for {
		f, _, batch, err := aether.ReadNextFrame(peer, rx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		frames := batch
		if f != nil {
			frames = []*aether.Frame{f}
		}
		for _, fr := range frames {
			if fr.Type != aether.TypeDATA || fr.Length == 0 || fr.Flags.Has(aether.FlagSYN) {
				continue
			}
			if fr.IsFragment() || fr.Length != uint32(len(msg)) {
				t.Fatalf("DATA frame of %d bytes, fragment %v; want one unflagged %d-byte frame", fr.Length, fr.IsFragment(), len(msg))
			}
			return
		}
	}
}

// TestTCPSession_RefusesFragments: a TCPSession delivers an unflagged payload
// beginning with the bytes 'F', 'R', 0, 1 as it is, and never delivers a
// flagged fragment, which it has no realm to check.
func TestTCPSession_RefusesFragments(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := aether.ReadWireVersionsPreface(peer); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(peer, aether.AetherWireVersions()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	frBytes := append([]byte{'F', 'R', 0, 1}, "hello"...)
	env := fxEnvelope()
	env.StreamID, env.Index, env.Total, env.OriginalLength = 10, 0, 1, 5000
	envelope := fxFragment(env, bytes.Repeat([]byte{'b'}, 5000))
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Generation: 1})
	writeFrames(t, peer,
		&aether.Frame{StreamID: 10, Type: aether.TypeDATA, Flags: aether.FlagSYN, Payload: openPayload},
		&aether.Frame{StreamID: 10, Type: aether.TypeDATA, Payload: frBytes},
		&aether.Frame{StreamID: 10, Type: aether.TypeDATA, Flags: aether.FlagFRAGMENT, Payload: envelope},
		&aether.Frame{StreamID: 10, Type: aether.TypeDATA, Payload: []byte("after")})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	for _, want := range [][]byte{frBytes, []byte("after")} {
		got, err := st.Receive(ctx)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("receive %q, %v; want %q", got, err, want)
		}
	}
	if sess.IsClosed() {
		t.Fatalf("a refused fragment closed the session")
	}
}

// packetPipe is one end of a buffered in-memory connection that never merges
// two Writes into one Read, as the browser's WebSocket and the agent's
// carrier stream do, with a queue between the ends so a Write never waits on
// the peer's readLoop. Two NoiseSessions need that: the noiseConn under each
// decrypts one packet per Read (runReader), so loopbackPair's TCP, which
// coalesces writes, is not a substrate it runs over, and net.Pipe hands each
// Write to the reader directly, so the two readLoops stall on each other's
// ACKs once the in-flight window outgrows the inbox. A Read with a buffer
// shorter than the packet takes its first bytes and leaves the rest for the
// next Read, which is how the handshake's io.ReadFull of a length prefix
// (ReadTicketAndFrame, readFrame) reads out of one packet. A deadline past
// zero times a blocked Read or Write out with an error that reports Timeout,
// which runReader treats as a retry, as DialOverConn and AcceptOverConn set
// and clear around the handshake.
type packetPipe struct {
	in         <-chan []byte
	out        chan<- []byte
	closed     chan struct{}
	peerClosed chan struct{}
	closeOnce  sync.Once

	// pending is the unread tail of the packet the last Read took from; Read
	// is called from one goroutine at a time, as net.Conn readers are.
	pending []byte

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// packetPipePair returns the two ends of a packetPipe holding up to depth
// packets in each direction.
func packetPipePair(depth int) (a, b net.Conn) {
	ab := make(chan []byte, depth)
	ba := make(chan []byte, depth)
	closedA, closedB := make(chan struct{}), make(chan struct{})
	return &packetPipe{in: ba, out: ab, closed: closedA, peerClosed: closedB},
		&packetPipe{in: ab, out: ba, closed: closedB, peerClosed: closedA}
}

type packetPipeTimeout struct{}

func (packetPipeTimeout) Error() string   { return "packet pipe: deadline exceeded" }
func (packetPipeTimeout) Timeout() bool   { return true }
func (packetPipeTimeout) Temporary() bool { return true }

type packetPipeAddr struct{}

func (packetPipeAddr) Network() string { return "packet-pipe" }
func (packetPipeAddr) String() string  { return "packet-pipe" }

// deadlineTimer returns a channel that fires at d, or nil (never fires) for a
// zero d, so a select on it waits only when a deadline is set.
func deadlineTimer(d time.Time) <-chan time.Time {
	if d.IsZero() {
		return nil
	}
	return time.After(time.Until(d))
}

// take copies the head of pkt into b and keeps the rest as pending.
func (p *packetPipe) take(b, pkt []byte) int {
	n := copy(b, pkt)
	p.pending = pkt[n:]
	return n
}

func (p *packetPipe) Read(b []byte) (int, error) {
	if len(p.pending) > 0 {
		return p.take(b, p.pending), nil
	}
	p.mu.Lock()
	timer := deadlineTimer(p.readDeadline)
	p.mu.Unlock()
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case pkt := <-p.in:
		return p.take(b, pkt), nil
	case <-p.peerClosed:
		// Packets the peer wrote before closing are still delivered.
		select {
		case pkt := <-p.in:
			return p.take(b, pkt), nil
		default:
			return 0, io.EOF
		}
	case <-p.closed:
		return 0, io.ErrClosedPipe
	case <-timer:
		return 0, packetPipeTimeout{}
	}
}

func (p *packetPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	timer := deadlineTimer(p.writeDeadline)
	p.mu.Unlock()
	pkt := append([]byte(nil), b...)
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	case <-p.peerClosed:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case p.out <- pkt:
		return len(b), nil
	case <-p.closed:
		return 0, io.ErrClosedPipe
	case <-p.peerClosed:
		return 0, io.ErrClosedPipe
	case <-timer:
		return 0, packetPipeTimeout{}
	}
}

func (p *packetPipe) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *packetPipe) LocalAddr() net.Addr  { return packetPipeAddr{} }
func (p *packetPipe) RemoteAddr() net.Addr { return packetPipeAddr{} }

func (p *packetPipe) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline, p.writeDeadline = t, t
	return nil
}

func (p *packetPipe) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	return nil
}

func (p *packetPipe) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeDeadline = t
	return nil
}

// overConnGrantPair runs DialSessionOverConn and AcceptSessionOverConn as the
// browser client and the agent do: the dialer carries a signed grant naming a
// partition and a target, the accepter verifies it, and both ends read the
// grant's realm through grantRealm, nil for a pair with no grant and no signer.
// The substrate is a packetPipePair deep enough that no write of the test's
// messages waits on the peer.
func overConnGrantPair(t *testing.T, grantRealm func([]byte) (noise.GrantRealm, error)) (dialer, accepter *NoiseSession) {
	t.Helper()
	kp := func() fnoise.DHKey {
		k, err := fnoise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		return k
	}
	acc, dia := kp(), kp()
	var ticket []byte
	acceptCfg := noise.AcceptConnConfig{LocalNodeID: "vl1_acc", StaticPriv: acc.Private, StaticPub: acc.Public, HandshakeTimeout: 3 * time.Second}
	if grantRealm != nil {
		signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		body := []byte(`{"target":"vl1_acc","scope":"partition-A"}`)
		ticket = append(body, ed25519.Sign(signerPriv, body)...)
		acceptCfg.TrustedTicketSigner = signerPub
		acceptCfg.GrantRealmFn = grantRealm
	}
	cc, sc := packetPipePair(4096)
	t.Cleanup(func() { _ = cc.Close(); _ = sc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := make(chan *NoiseSession, 1)
	go func() {
		s, err := AcceptSessionOverConn(ctx, acceptCfg, sc, aether.DefaultSessionOptions())
		if err != nil {
			t.Errorf("accept: %v", err)
		}
		out <- s
	}()
	d, err := DialSessionOverConn(ctx, noise.DialConnConfig{
		LocalNodeID: "vl1_dia", StaticPriv: dia.Private, StaticPub: dia.Public,
		Ticket: ticket, GrantRealmFn: grantRealm, HandshakeTimeout: 3 * time.Second,
	}, cc, aether.DefaultSessionOptions())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-out
	if a == nil {
		t.FailNow()
	}
	t.Cleanup(func() { _ = d.Close(); _ = a.Close() })
	return d, a
}

// realmFromTestGrant reads the partition and target the test grant carries.
func realmFromTestGrant(body []byte) (noise.GrantRealm, error) {
	var g struct {
		Scope  string `json:"scope"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		return noise.GrantRealm{}, err
	}
	return noise.GrantRealm{Partition: g.Scope, Target: g.Target}, nil
}

// TestNoiseSession_OverConnGrantRealmCarriesFragments: an over-conn session
// whose handshake bound the grant's realm sends a message many frames long,
// and the accepter receives it whole; both ends carry the grant's realm id.
// One with no grant binds no realm and refuses such a message, typed. The
// message is larger than any frame the session's MSS admits, which the test
// checks, so it travels in fragments or not at all; it is smaller than the
// session's inbox (noise DefaultInboxSize packets), so the test holds the
// realm binding and not loss recovery, which
// TestNoiseSession_LargeMessageRoundTripsInFragments holds on a mesh session.
func TestNoiseSession_OverConnGrantRealmCarriesFragments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d, a := overConnGrantPair(t, realmFromTestGrant)
	want, err := noise.GrantRealm{Partition: "partition-A", Target: "vl1_acc"}.ID()
	if err != nil {
		t.Fatalf("realm id: %v", err)
	}
	for name, s := range map[string]*NoiseSession{"dialer": d, "accepter": a} {
		if !s.realmBound || s.realmID != want {
			t.Fatalf("%s session realm %08x, %v; want the grant's %08x, true", name, s.realmID, s.realmBound, want)
		}
	}
	if _, ok := d.WireVersions().Version(aether.WireVersionFragment); !ok {
		t.Fatalf("over-conn session chose no fragment envelope: %v", d.WireVersions())
	}
	msg := make([]byte, 20_000)
	for i := range msg {
		msg[i] = byte(i*7 + 3)
	}
	cs, as := openAccept(t, ctx, d, a, 10)
	if max := MSSToMaxPayload(d.MSS()); len(msg) <= max {
		t.Fatalf("the %d-byte message fits one %d-byte frame; the test needs fragments", len(msg), max)
	}
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("a %d-byte message on an over-conn session with a grant: %v", len(msg), err)
	}
	got, err := as.Receive(ctx)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("received %d bytes, %v; want the %d sent intact", len(got), err, len(msg))
	}

	d2, a2 := overConnGrantPair(t, nil)
	if d2.realmBound || a2.realmBound {
		t.Fatalf("an over-conn session with no grant bound a realm")
	}
	cs2, _ := openAccept(t, ctx, d2, a2, 10)
	if max := MSSToMaxPayload(d2.MSS()); len(msg) <= max {
		t.Fatalf("the %d-byte message fits one %d-byte frame; the test needs fragments", len(msg), max)
	}
	wantRefusal(t, "a large message on an over-conn session with no grant", cs2.Send(ctx, msg), FragmentNoRealm)
}
