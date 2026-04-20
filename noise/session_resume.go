//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// 0-RTT session resumption initiator-side plumbing. Concern S-ticket /
// remediation item #1.
//
// Overview — how resumption works end-to-end:
//
//  1. **Responder issues a ticket** after a successful XK/XX handshake
//     (`handshake.go:590`). The ticket is encrypted with a transport-
//     local AES-256-GCM key and contains the full Noise CipherState
//     (SendKey, RecvKey, Nonce, Caps) keyed for the responder's
//     perspective.
//
//  2. **Responder hands ticket + plaintext keys to the initiator** via
//     a `HANDSHAKE_RESUME_MATERIAL` control frame (sent inside the now-
//     encrypted session). The initiator can't decrypt the opaque
//     ticket blob (it doesn't know the responder's ticket key) but
//     needs the raw cipher keys in-hand to drive its own CipherState
//     on next resume. Since the control frame travels over the just-
//     established encrypted channel, the plaintext-key hand-off is
//     confidential.
//
//  3. **Initiator caches** (opaque ticket, initiator-perspective send
//     key, initiator-perspective recv key, expiry) keyed by
//     peer NodeID. The initiator perspective is simply a swap of the
//     responder-perspective keys (Noise XX produces two CipherStates —
//     cs1 and cs2 — each party's `send` is the other's `recv`).
//
//  4. **Initiator resumes on next Dial**: sends a single UDP datagram
//     prefixed with resumePrefix (0xFD), containing the opaque ticket
//     followed by an empty encrypted frame (nonce=0, empty payload)
//     encrypted with the initiator's send key. The responder decrypts
//     the ticket with its own key, derives its CipherState from the
//     stored SendKey/RecvKey, verifies the trailer frame's AEAD tag
//     (integrity proof that initiator really holds the keys), then
//     promotes the resumed session to active.
//
//  5. **Rollback**: if the responder rejects resume (ticket expired,
//     key rotated out of overlap window, AEAD tag mismatch, etc.) it
//     replies with a plaintext reject packet prefixed with
//     resumeRejectPrefix (0xFC). The initiator evicts the ticket and
//     falls back to a full XK handshake.
//
// Rollback + replay protection:
//
//   - Each ticket is single-use from the responder's perspective: once
//     `DecryptTicket` succeeds and a session is instantiated, the
//     ticket's Nonce is recorded in seenTickets. Replays hit the nonce
//     cache and are rejected with resumeRejectPrefix.
//   - 0-RTT application data is NOT sent with the resume packet. This
//     keeps the design at 0.5-RTT — initiator must wait for responder's
//     first frame before sending data. Trade-off: loses the headline
//     0-RTT latency win but sidesteps replay-safety concerns (see QUIC
//     RFC 9001 §9.2 for why 0-RTT data is dangerous).
package noise

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	fnoise "github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
)

// Wire prefixes for the resume sub-protocol. Chosen from the high-byte
// range to avoid collision with existing prefixes: 0xFE is retryPrefix,
// 0xFD is dialNoncePrefix. We take 0xFA/0xF9/0xF8 below those. All are
// distinguishable from Noise handshake message bytes (Noise msg1
// starts with an ephemeral public key — 32 bytes of high-entropy data,
// never a fixed sentinel) and from STUN (0x00–0x3F) / QUIC (0x40–0xBF).
const (
	resumePrefix       byte = 0xFA // initiator → responder: 0.5-RTT resume attempt
	resumeRejectPrefix byte = 0xF9 // responder → initiator: resume rejected, fall back
	resumeAcceptPrefix byte = 0xF8 // responder → initiator: resume accepted, empty ACK
)

// resumeMaterial is the initiator-side view of a ticket. Paired with
// the responder's opaque encrypted blob so the initiator knows which
// keys to use for its own CipherState on resume.
type resumeMaterial struct {
	Opaque    []byte    // responder's encrypted ticket — replayed verbatim
	SendKey   [32]byte  // initiator's send key (= responder's recv)
	RecvKey   [32]byte  // initiator's recv key (= responder's send)
	Caps      uint32    // capabilities negotiated in the original session
	ExpiresAt time.Time // copied from ticket; initiator enforces locally too
}

// initiatorTicketCache is the initiator-side ticket cache. Separate from
// TicketStore (which is responder-side — it holds the AES key used to
// encrypt tickets) because the two stores have very different trust
// assumptions: responder-side is the root of trust, initiator-side is
// just a replay buffer.
type initiatorTicketCache struct {
	mu      sync.Mutex
	entries map[aether.NodeID]*resumeMaterial
	order   []aether.NodeID
	max     int
}

func newInitiatorTicketCache(max int) *initiatorTicketCache {
	if max <= 0 {
		max = DefaultTicketCacheSize
	}
	return &initiatorTicketCache{
		entries: make(map[aether.NodeID]*resumeMaterial),
		max:     max,
	}
}

// Store caches resume material for a peer. FIFO eviction matches
// TicketStore's model.
func (c *initiatorTicketCache) Store(peerID aether.NodeID, m *resumeMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[peerID]; !ok {
		if len(c.order) >= c.max {
			old := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, old)
		}
		c.order = append(c.order, peerID)
	}
	c.entries[peerID] = m
}

// Lookup retrieves resume material for a peer. Expired entries are
// lazily evicted.
func (c *initiatorTicketCache) Lookup(peerID aether.NodeID) *resumeMaterial {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.entries[peerID]
	if !ok {
		return nil
	}
	if !m.ExpiresAt.IsZero() && time.Now().After(m.ExpiresAt) {
		c.evictLocked(peerID)
		return nil
	}
	return m
}

// Evict removes a peer's material (called on rollback + expiry).
func (c *initiatorTicketCache) Evict(peerID aether.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked(peerID)
}

func (c *initiatorTicketCache) evictLocked(peerID aether.NodeID) {
	if _, ok := c.entries[peerID]; !ok {
		return
	}
	delete(c.entries, peerID)
	for i, id := range c.order {
		if id == peerID {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// encodeResumeMaterial serialises resume material for wire transmission
// from responder to initiator (inside the encrypted session via
// HANDSHAKE frame). Format:
//
//	[2B opaqueLen][opaque...][32B SendKey][32B RecvKey][4B Caps][8B ExpiresUnixNano]
func encodeResumeMaterial(m *resumeMaterial) []byte {
	buf := make([]byte, 0, 2+len(m.Opaque)+32+32+4+8)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(m.Opaque)))
	buf = append(buf, lenBuf...)
	buf = append(buf, m.Opaque...)
	buf = append(buf, m.SendKey[:]...)
	buf = append(buf, m.RecvKey[:]...)
	capsBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(capsBuf, m.Caps)
	buf = append(buf, capsBuf...)
	expBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(expBuf, uint64(m.ExpiresAt.UnixNano()))
	buf = append(buf, expBuf...)
	return buf
}

// decodeResumeMaterial parses the encoded resume material delivered
// inside a HANDSHAKE_RESUME_MATERIAL control frame.
func decodeResumeMaterial(data []byte) (*resumeMaterial, error) {
	if len(data) < 2 {
		return nil, errors.New("resume material: short buffer")
	}
	opaqueLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+opaqueLen+32+32+4+8 {
		return nil, errors.New("resume material: truncated")
	}
	m := &resumeMaterial{
		Opaque: append([]byte(nil), data[2:2+opaqueLen]...),
	}
	p := 2 + opaqueLen
	copy(m.SendKey[:], data[p:p+32])
	p += 32
	copy(m.RecvKey[:], data[p:p+32])
	p += 32
	m.Caps = binary.BigEndian.Uint32(data[p : p+4])
	p += 4
	m.ExpiresAt = time.Unix(0, int64(binary.BigEndian.Uint64(data[p:p+8])))
	return m, nil
}

// seenTicketNonces bounds replay protection: every resumed session's
// ticket nonce is recorded; duplicates are rejected. FIFO eviction at
// DefaultSeenTicketCacheSize keeps the map from growing unbounded.
const DefaultSeenTicketCacheSize = 16384

type seenTicketCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	order   []string
	max     int
}

func newSeenTicketCache(max int) *seenTicketCache {
	if max <= 0 {
		max = DefaultSeenTicketCacheSize
	}
	return &seenTicketCache{
		seen: make(map[string]time.Time),
		max:  max,
	}
}

// MarkOrReject attempts to record a ticket nonce as seen. Returns true
// if the nonce was novel (admit resume) and false if it has been seen
// before within the cache window (reject).
func (c *seenTicketCache) MarkOrReject(nonce []byte) bool {
	key := string(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return false
	}
	if len(c.order) >= c.max {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.seen, old)
	}
	c.order = append(c.order, key)
	c.seen[key] = time.Now()
	return true
}

// tryResumeDial attempts a 0.5-RTT resumption against target. Returns
// (nil, nil) on "no ticket cached, caller should do full handshake"
// rather than an error — distinguishes "no attempt made" from "attempted
// and failed." Returns (conn, nil) on success. Returns (nil, err) on
// hard failure (ticket expired locally, network unreachable, etc.) —
// caller may still fall back to full handshake.
//
// NOTE: the actual transport-level wire exchange lives in
// dialResumePacket — this function is the policy layer that decides
// whether to attempt, reads/writes the UDP, and wires the result back
// into the transport's session table.
func (t *NoiseTransport) tryResumeDial(ctx interface{}, target aether.Target, udp *net.UDPConn, remoteAddr *net.UDPAddr) (*noiseConn, error) {
	if t.initiatorTickets == nil {
		return nil, nil // cache not initialised — no resume available
	}
	m := t.initiatorTickets.Lookup(target.NodeID)
	if m == nil {
		return nil, nil // no ticket for this peer
	}
	// Expired locally — evict and skip.
	if !m.ExpiresAt.IsZero() && time.Now().After(m.ExpiresAt) {
		t.initiatorTickets.Evict(target.NodeID)
		return nil, nil
	}

	// Build resume packet: [resumePrefix][2B opaqueLen][opaque ticket][12B nonce][16B AEAD tag over empty msg].
	// The AEAD tag proves the initiator actually holds the claimed key.
	send, recv, err := buildInitiatorCipherStates(m.SendKey, m.RecvKey)
	if err != nil {
		return nil, fmt.Errorf("build cipher states from ticket: %w", err)
	}

	pkt := make([]byte, 0, 1+2+len(m.Opaque)+16)
	pkt = append(pkt, resumePrefix)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(m.Opaque)))
	pkt = append(pkt, lenBuf...)
	pkt = append(pkt, m.Opaque...)
	// Seal an empty plaintext — the tag serves as initiator-possesses-
	// key proof. Responder will Open(tag) against its derived CipherState.
	// flynn/noise's Encrypt signature is (out, ad, plaintext) → (ct, err);
	// ct carries just the AEAD tag when plaintext is empty.
	tag, encErr := send.Encrypt(nil, nil, nil)
	if encErr != nil {
		return nil, fmt.Errorf("resume: seal proof tag: %w", encErr)
	}
	pkt = append(pkt, tag...)

	if _, err := udp.WriteToUDP(pkt, remoteAddr); err != nil {
		return nil, fmt.Errorf("resume: write: %w", err)
	}

	// Wait for accept/reject. Responder replies with either
	// resumeAcceptPrefix + AEAD-sealed empty payload (proof of key
	// possession on their side) or resumeRejectPrefix.
	readBuf := make([]byte, 256)
	if err := udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	defer udp.SetReadDeadline(time.Time{})
	n, src, err := udp.ReadFromUDP(readBuf)
	if err != nil {
		return nil, fmt.Errorf("resume: read: %w", err)
	}
	if src.String() != remoteAddr.String() {
		return nil, fmt.Errorf("resume: response from wrong source")
	}
	if n < 1 {
		return nil, fmt.Errorf("resume: empty response")
	}
	switch readBuf[0] {
	case resumeRejectPrefix:
		// Responder rejected — evict cache entry, let caller fall back.
		t.initiatorTickets.Evict(target.NodeID)
		return nil, errResumeRejected
	case resumeAcceptPrefix:
		// Verify responder's empty-frame tag to prove they derived
		// the same keys. readBuf[1:n] must be exactly a 16-byte tag.
		if n != 1+16 {
			return nil, fmt.Errorf("resume: bad accept length %d", n)
		}
		if _, err := recv.Decrypt(nil, nil, readBuf[1:n]); err != nil {
			return nil, fmt.Errorf("resume: accept tag verify failed: %w", err)
		}
		// Resume confirmed — instantiate noiseConn with resumed states.
		// Caller owns wiring it into the listener's session table.
		nc := newNoiseConnDial(udp, remoteAddr, target.NodeID, send, recv, t.maxPacket, t)
		return nc, nil
	default:
		return nil, fmt.Errorf("resume: unknown response prefix 0x%02x", readBuf[0])
	}
}

// errResumeRejected signals that the responder explicitly rejected
// resume (ticket expired, rotated key, etc.) — caller should fall
// back to full handshake.
var errResumeRejected = errors.New("resume: responder rejected ticket")

// deliverResumeMaterial sends the encoded resume material to the
// initiator as the first encrypted frame on the newly-established
// session. Wrapped in an Aether HANDSHAKE frame so the initiator's
// adapter routes it via handleHandshake without needing a custom UDP
// demux path. Failures are logged but non-fatal — a successful
// handshake should not be torn down just because the peer missed its
// resume ticket; they'll re-establish with a full handshake next time.
//
// Nonce accounting: this consumes cs2 nonce 0 on the responder's send
// path. The corresponding decrypt on the initiator consumes cs2
// nonce 0 on the recv path. Both sides advance to nonce 1 for
// subsequent session traffic. Ticket snapshot (which captured nonce=0
// on both CipherStates at issuance time) remains valid for the next
// resume attempt because resume creates fresh CipherStates starting
// from nonce=0 — independent of the current session's live nonce.
func deliverResumeMaterial(nc *noiseConn, m *resumeMaterial) {
	encoded := encodeResumeMaterial(m)
	payload := aether.EncodeHandshake(aether.HandshakePayload{
		HandshakeType: aether.HandshakeResumeMaterial,
		Payload:       encoded,
	})
	frame := &aether.Frame{
		Type:    aether.TypeHANDSHAKE,
		Length:  uint32(len(payload)),
		Payload: payload,
	}
	frameBytes := aether.EncodeFrameToBytes(frame)
	// nc.Write routes through cs2 encryption; a single write is
	// atomic at the UDP datagram level.
	if _, err := nc.Write(frameBytes); err != nil {
		dbgNoise.Printf("resume: deliver material to %s failed: %v", nc.remoteNode.Short(), err)
	}
}

// handleResumePacket is the responder-side entry point for 0.5-RTT
// resume attempts. Called by the listener's read loop when a datagram
// prefixed with resumePrefix (0xFD) arrives. The packet layout is:
//
//	[1B prefix=0xFD][2B opaqueLen][opaqueLen bytes ticket][16B AEAD proof tag]
//
// Steps:
//  1. Parse the packet.
//  2. Decrypt the ticket with the transport's TicketStore (rotates
//     between current + previous keys).
//  3. Reject if the ticket has been seen before (replay guard via
//     seenTickets cache keyed by ticket nonce).
//  4. Reconstruct the responder's CipherStates from the ticket's
//     SendKey/RecvKey (responder-perspective).
//  5. Verify the initiator's AEAD proof tag by decrypting the empty
//     trailer — proves the initiator actually holds the RecvKey
//     claimed by the ticket (defence against ticket theft).
//  6. On success: send resumeAcceptPrefix + our own AEAD proof tag.
//  7. On failure: send resumeRejectPrefix so the initiator evicts
//     its cached ticket and falls back to a full handshake.
func (l *noiseListener) handleResumePacket(ctx context.Context, conn *net.UDPConn, pkt []byte, addr *net.UDPAddr) {
	// Send-or-reject helper.
	sendReject := func() {
		_, _ = conn.WriteToUDP([]byte{resumeRejectPrefix}, addr)
	}

	if l.transport.ticketStore == nil {
		sendReject()
		return
	}
	if len(pkt) < 1+2+ticketNonceSize+ticketTagSize {
		sendReject()
		return
	}
	opaqueLen := int(binary.BigEndian.Uint16(pkt[1:3]))
	if opaqueLen <= 0 || 3+opaqueLen+16 > len(pkt) {
		sendReject()
		return
	}
	opaque := pkt[3 : 3+opaqueLen]
	proofTag := pkt[3+opaqueLen : 3+opaqueLen+16]

	ticket, err := l.transport.ticketStore.DecryptTicket(opaque)
	if err != nil {
		dbgNoise.Printf("resume: decrypt failed from %s: %v", addr, err)
		sendReject()
		return
	}

	// Replay protection: reject if the same ticket nonce has already
	// been consumed. Use the first 12 bytes of the opaque blob (GCM
	// nonce) as the cache key — guaranteed unique per IssueTicket call
	// because rand.Read produces 96 bits of entropy.
	replayKey := opaque[:ticketNonceSize]
	if l.transport.seenTickets != nil {
		if !l.transport.seenTickets.MarkOrReject(replayKey) {
			dbgNoise.Printf("resume: replay detected from %s", addr)
			sendReject()
			return
		}
	}

	// Responder CipherStates: ticket stores them from the responder's
	// perspective (SendKey = responder-to-initiator, RecvKey =
	// initiator-to-responder), matching IssueTicket's layout.
	send, recv, err := buildInitiatorCipherStates(ticket.SendKey, ticket.RecvKey)
	if err != nil {
		sendReject()
		return
	}

	// Verify initiator's proof tag: initiator's send = responder's recv,
	// so we decrypt with `recv`.
	if _, err := recv.Decrypt(nil, nil, proofTag); err != nil {
		dbgNoise.Printf("resume: initiator proof tag invalid from %s: %v", addr, err)
		sendReject()
		return
	}

	// Build accept reply: our own proof tag sealed with `send`.
	replyTag, err := send.Encrypt(nil, nil, nil)
	if err != nil {
		sendReject()
		return
	}
	reply := make([]byte, 0, 1+len(replyTag))
	reply = append(reply, resumeAcceptPrefix)
	reply = append(reply, replyTag...)
	if _, err := conn.WriteToUDP(reply, addr); err != nil {
		dbgNoise.Printf("resume: write accept: %v", err)
		return
	}

	// Instantiate the resumed noiseConn and register it in the listener's
	// session table so subsequent packets route correctly.
	nc := newNoiseConnListener(l, send, recv, addr, ticket.PeerID)
	key := addr.String()
	l.mu.Lock()
	l.sessions.Put(ticket.PeerID, key, "", &noiseConnSession{conn: nc, nodeID: ticket.PeerID})
	l.mu.Unlock()

	// Deliver to the incoming-session channel so the application layer
	// sees the resumed session just like any XK/XX-established one.
	s := aether.NewConnection(l.transport.localNode, ticket.PeerID, nc)
	s.OnClose(func() { nc.Close() })
	select {
	case l.incoming <- aether.IncomingSession{Session: s, Reader: nc, Writer: nc}:
	case <-ctx.Done():
	}
	dbgNoise.Printf("resume: accepted session with %s via 0.5-RTT ticket", ticket.PeerID.Short())
}

// buildInitiatorCipherStates recreates flynn/noise CipherStates from
// raw keys so the initiator can drive its send/recv channels after
// ticket-based resumption. Uses `UnsafeNewCipherState` — the library's
// documented helper for exactly this scenario (its comment reads
// "Intended to be used alongside UnsafeNewCipherState to resume a
// session" — present since flynn/noise v1.1.0).
//
// The cipher suite must match what the original handshake used.
// aether hard-wires XK/XX with Curve25519 / ChaCha20-Poly1305 /
// BLAKE2b — we reconstruct the same suite via fnoise.NewCipherSuite.
// Nonce=0 because the ticket issuer rejected issuance unless both
// CipherStates were pristine (nonce==0 check at session_ticket.go:177).
func buildInitiatorCipherStates(sendKey, recvKey [32]byte) (*fnoise.CipherState, *fnoise.CipherState, error) {
	cs := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashBLAKE2b)
	send := fnoise.UnsafeNewCipherState(cs, sendKey, 0)
	recv := fnoise.UnsafeNewCipherState(cs, recvKey, 0)
	if send == nil || recv == nil {
		return nil, nil, errors.New("resume: UnsafeNewCipherState returned nil")
	}
	return send, recv, nil
}
