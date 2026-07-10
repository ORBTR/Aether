//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"bytes"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// helper: open a UDP socket on loopback and return the *net.UDPConn +
// the local addr. Caller closes.
func newLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// helper: open a IPv6 loopback UDP socket. Some test environments (CI
// containers) have no IPv6 loopback configured — those tests skip.
func newLoopbackUDP6(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
		return nil
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// synthListener builds a minimal *noiseListener with only the fields
// the writeFunc reads — transport (for forwarder lookup) and conn(s)
// (for connFor() socket selection). Tests use this to exercise the
// writeFunc without spinning a full transport.
func synthListener(nt *NoiseTransport, ipv4 *net.UDPConn) *noiseListener {
	return &noiseListener{transport: nt, conn: ipv4}
}

// synthListenerDualStack builds a listener with BOTH IPv4 and IPv6
// sockets — required for tests that exercise connFor() picking the v6
// socket for an IPv6 relay destination.
func synthListenerDualStack(nt *NoiseTransport, ipv4, ipv6 *net.UDPConn) *noiseListener {
	return &noiseListener{transport: nt, conn: ipv4, ipv6Conn: ipv6}
}

// buildListenerWriteFunc — test-only thin wrapper that constructs a
// noiseConn-less writeFunc. Production code uses buildNoiseConnWriteFunc
// directly off a real noiseConn so the per-conn crossOrgPreambleTarget
// field is in scope; these tests don't need that side of the closure.
func buildListenerWriteFunc(l *noiseListener, remote *net.UDPAddr) func([]byte) (int, error) {
	var nc noiseConn // empty — no crossOrgPreambleTarget
	return buildNoiseConnWriteFunc(&nc, l, remote)
}

// TestListenerWriteFunc_NoForwarder verifies the writeFunc is a plain
// pass-through when the transport has no forwarder wired — this is the
// hot path for normal sessions.
func TestListenerWriteFunc_NoForwarder(t *testing.T) {
	sender := newLoopbackUDP(t)
	receiver := newLoopbackUDP(t)
	recvAddr := receiver.LocalAddr().(*net.UDPAddr)

	wf := buildListenerWriteFunc(synthListener(nil, sender), recvAddr)
	payload := []byte("plain noise frame")
	n, err := wf(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("n=%d want=%d", n, len(payload))
	}

	buf := make([]byte, 2048)
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	rn, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiver read: %v", err)
	}
	if !bytes.Equal(buf[:rn], payload) {
		t.Fatalf("received %q, want %q (the no-forwarder path must not wrap)", buf[:rn], payload)
	}
}

// TestListenerWriteFunc_NoTTableEntry verifies that with a forwarder
// configured but no T-table entry for the destination, writes still
// flow through unchanged — only registered relayed sources get wrapped.
func TestListenerWriteFunc_NoTTableEntry(t *testing.T) {
	sender := newLoopbackUDP(t)
	receiver := newLoopbackUDP(t)
	recvAddr := receiver.LocalAddr().(*net.UDPAddr)

	fwd, _ := newTestForwarder(t, nil)
	nt := &NoiseTransport{forwarder: fwd}

	wf := buildListenerWriteFunc(synthListener(nt, sender), recvAddr)
	payload := []byte("normal write — no relay")
	if _, err := wf(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	rn, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:rn], payload) {
		t.Fatalf("unregistered remote should bypass wrapping; got %x", buf[:rn])
	}
}

// TestListenerWriteFunc_RelayWrapsOpReply verifies the M_t side: when
// the destination is in the T-table, the writeFunc must wrap the msg in
// an OpReply frame and send to the relay (M_r) addr instead of the
// originator's public addr.
func TestListenerWriteFunc_RelayWrapsOpReply(t *testing.T) {
	sender := newLoopbackUDP(t)
	relay := newLoopbackUDP(t)   // stands in for M_r
	origin := newLoopbackUDP(t)  // stands in for the originator's public addr
	relayAddr := relay.LocalAddr().(*net.UDPAddr)
	originAddr := origin.LocalAddr().(*net.UDPAddr)

	fwd, _ := newTestForwarder(t, nil)
	flowID := NewFlowID()
	// Simulate: M_t received an OpForward for `originAddr` via `relayAddr`.
	fwd.RegisterRelayed(originAddr, relayAddr, flowID)

	nt := &NoiseTransport{forwarder: fwd}

	// writeFunc is constructed against the originator addr — the noise
	// session sees the originator as the "remote" because the listener
	// injected the payload with substAddr=originator on ingress.
	wf := buildListenerWriteFunc(synthListener(nt, sender), originAddr)
	plaintext := []byte("noise msg2 reply payload")
	n, err := wf(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// The function reports the plaintext length, not the wire length —
	// the noise layer counts payload bytes, not transport wrapping.
	if n != len(plaintext) {
		t.Fatalf("reported n=%d want=%d (plaintext length)", n, len(plaintext))
	}

	// The originator socket must NOT receive anything — the reply goes
	// to the relay instead.
	_ = origin.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 2048)
	if rn, _, err := origin.ReadFromUDP(buf); err == nil {
		t.Fatalf("originator received %d bytes — relay-aware writeFunc should have routed to M_r instead", rn)
	}

	// The relay socket MUST receive an OpReply frame carrying the
	// plaintext payload.
	_ = relay.SetReadDeadline(time.Now().Add(time.Second))
	rn, _, err := relay.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("relay did not receive wrapped reply: %v", err)
	}
	if !IsInnerRelay(buf[:rn]) {
		t.Fatalf("relay received non-inner-relay bytes: %x", buf[:rn])
	}
	dec, err := DecodeInnerRelay(buf[:rn])
	if err != nil {
		t.Fatal(err)
	}
	if dec.Op != OpReply {
		t.Fatalf("op=%d want OpReply (%d)", dec.Op, OpReply)
	}
	if dec.FlowID != flowID {
		t.Fatal("FlowID mismatch in wrapped reply")
	}
	if !bytes.Equal(dec.Payload, plaintext) {
		t.Fatalf("wrapped payload mismatch: got %x want %x", dec.Payload, plaintext)
	}
}

// TestOnRoutingPreamble_DropsUnknownTarget verifies the M_r path when
// the routing-preamble target isn't in the directory: the function MUST
// return consumed=true (so the caller doesn't fall through to noise
// dispatch with junk bytes), MUST bump the targetUnknown drop counter,
// and MUST NOT emit any OpForward upstream.
func TestOnRoutingPreamble_DropsUnknownTarget(t *testing.T) {
	// The lookup is a stub that always returns "not found".
	fwd, localNID := newTestForwarder(t, func(target aether.NodeID) (*net.UDPAddr, bool) {
		return nil, false
	})
	_ = localNID

	// Spy socket — we use a listener whose ipv6Conn would be the target
	// for any OpForward write. If the test sees ANYTHING on this socket,
	// the drop path wasn't taken.
	spy := newLoopbackUDP6(t)
	if spy == nil {
		return
	}
	v4 := newLoopbackUDP(t)
	nt := &NoiseTransport{forwarder: fwd}
	l := synthListenerDualStack(nt, v4, spy)

	// Build a routing-preamble packet for a target that the lookup
	// rejects (any non-local NodeID).
	preamble := EncodeRoutingPreamble(aether.NodeID("vl1_unknown_unknown_unknown_uu"))
	pkt := append(preamble, []byte("fake msg1 bytes")...)

	preBefore, tgtBefore, _, _, _, _ := fwd.Drops()
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 999}
	substBuf, substAddr, consumed := l.onRoutingPreamble(fwd, pkt, addr, v4)

	if !consumed {
		t.Fatal("consumed=false on unknown target — caller would fall through to noise dispatch with garbage")
	}
	if substBuf != nil || substAddr != nil {
		t.Fatalf("substBuf=%v substAddr=%v want both nil", substBuf, substAddr)
	}
	preAfter, tgtAfter, _, _, _, _ := fwd.Drops()
	if tgtAfter != tgtBefore+1 {
		t.Fatalf("targetUnknown counter delta=%d want 1", tgtAfter-tgtBefore)
	}
	if preAfter != preBefore {
		t.Fatalf("preambleMalformed should not bump on a well-formed preamble with unknown target")
	}

	// The spy IPv6 socket must NOT have received anything.
	_ = spy.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, err := spy.ReadFromUDP(buf); err == nil {
		t.Fatalf("OpForward emitted to IPv6 socket on unknown target (%d bytes); should be dropped silently", n)
	}
}

// TestListenerWriteFunc_RelayPicksIPv6Socket_C1 is the regression test
// for the audit's C1 finding: when the destination addr is an IPv4
// originator but the T-table maps it to an IPv6 6PN relay, the writeFunc
// MUST use the IPv6 listener socket — not the IPv4 socket the
// originator's 5-tuple would naively pick.
//
// Without the fix, the OpReply would attempt to write to an IPv6 dest
// via the IPv4-only socket and fail; this test would observe the relay
// receiving zero bytes.
func TestListenerWriteFunc_RelayPicksIPv6Socket_C1(t *testing.T) {
	v4Conn := newLoopbackUDP(t)             // M_t IPv4 socket (origin reply path)
	v6Sender := newLoopbackUDP6(t)          // M_t IPv6 socket (relay write path)
	if v6Sender == nil {
		return // skipped above
	}
	v6Relay := newLoopbackUDP6(t)           // stands in for M_r's 6PN listener
	if v6Relay == nil {
		return
	}
	origin := newLoopbackUDP(t)             // IPv4 originator
	originAddr := origin.LocalAddr().(*net.UDPAddr)
	relayAddrV6 := v6Relay.LocalAddr().(*net.UDPAddr)

	fwd, _ := newTestForwarder(t, nil)
	flowID := NewFlowID()
	// Register: originator is IPv4, but the relay path is IPv6 — exactly
	// the production layout (originator on public anycast IPv4, M_r at
	// a 6PN IPv6 ULA).
	fwd.RegisterRelayed(originAddr, relayAddrV6, flowID)

	nt := &NoiseTransport{forwarder: fwd}
	l := synthListenerDualStack(nt, v4Conn, v6Sender)

	wf := buildListenerWriteFunc(l, originAddr)
	plaintext := []byte("ipv6-relay reply payload")
	if _, err := wf(plaintext); err != nil {
		t.Fatal(err)
	}

	// The IPv6 relay socket MUST receive the wrapped frame. If the
	// writeFunc had used the IPv4 socket (v4Conn) to address an IPv6
	// destination, the OS would have failed the write — this read times
	// out.
	_ = v6Relay.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	rn, _, err := v6Relay.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("IPv6 relay did not receive wrapped frame — C1 socket-selection bug regressed: %v", err)
	}
	if !IsInnerRelay(buf[:rn]) {
		t.Fatalf("relay received non-inner-relay bytes: %x", buf[:rn])
	}
	dec, err := DecodeInnerRelay(buf[:rn])
	if err != nil {
		t.Fatal(err)
	}
	if dec.Op != OpReply || dec.FlowID != flowID {
		t.Fatalf("decoded op=%d flow match=%v", dec.Op, dec.FlowID == flowID)
	}
	if !bytes.Equal(dec.Payload, plaintext) {
		t.Fatalf("payload mismatch: got %x want %x", dec.Payload, plaintext)
	}
}
