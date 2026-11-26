//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */

// 0.5-RTT session resumption, initiator side, and the responder's resume
// handler.
//
// Overview — how resumption works end-to-end:
//
//  1. **Responder issues a ticket** after a successful XK/XX handshake
//     (handleHandshake, once the session is in l.sessions). The ticket is
//     encrypted with a transport-local AES-256-GCM key and contains the
//     full Noise CipherState (SendKey, RecvKey, Nonce, Caps) keyed for the
//     responder's perspective.
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
//  4. **Initiator resumes on next Dial**: sends a UDP datagram prefixed
//     with resumePrefix (0xFA) carrying [opaque ticket][ephemeral X25519
//     pub][PSK-possession binder]. The responder decrypts the ticket for
//     the PSK, verifies the binder, performs a fresh X25519 exchange, and
//     derives FORWARD-SECRET per-resume traffic keys via HKDF(PSK ‖ DH)
//     bound to the transcript (see session_resume_keys.go). It replies
//     resumeAcceptPrefix with [its ephemeral pub][confirm-tag]; the
//     initiator does the same DH and derives identical keys. Because every
//     resume mixes a fresh ephemeral DH, no (key,nonce) pair is ever shared
//     with the original session or another resume (session_resume_keys.go).
//
//  5. **Rollback**: if the responder rejects resume (ticket expired, key
//     rotated out of overlap window, binder mismatch, replay, etc.) it
//     replies with a plaintext reject packet prefixed with
//     resumeRejectPrefix (0xF9). The initiator evicts the ticket and
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

	aether "github.com/ORBTR/aether"
	fnoise "github.com/flynn/noise"
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
	// PeerOffer is the wire version offer of the node this material resumes
	// to, and Chosen the set the original handshake chose. tryResumeDial
	// chooses again from this transport's offer and PeerOffer and skips the
	// resume when the result is not Chosen; a resumed conn reports Chosen.
	PeerOffer aether.WireVersions
	Chosen    aether.NegotiatedWireVersions
	// Realm is the mesh realm (the network key, on this transport) the
	// original session bound; the resumed conn reports it.
	Realm realmBinding
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
//	[2B peerOfferLen][peer offer][2B chosenLen][chosen set]
//	[5B realm binding, encodeRealmBinding]
//
// The two wire version fields are in the aether.WireVersions and
// aether.NegotiatedWireVersions encodings. The material is built only from a
// handshake's own validated offers, so the offer always encodes; one that did
// not would be written empty and refused by the initiator's resume check.
func encodeResumeMaterial(m *resumeMaterial) []byte {
	offer, err := m.PeerOffer.Encode()
	if err != nil {
		offer = nil
	}
	chosen := m.Chosen.Encode()
	buf := make([]byte, 0, 2+len(m.Opaque)+32+32+4+8+2+len(offer)+2+len(chosen))
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
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(offer)))
	buf = append(buf, offer...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(chosen)))
	buf = append(buf, chosen...)
	buf = append(buf, encodeRealmBinding(m.Realm)...)
	return buf
}

// decodeResumeMaterial parses the encoded resume material delivered
// inside a HANDSHAKE_RESUME_MATERIAL control frame, refusing a truncated
// field, a wire version field that is not a canonical encoding, and trailing
// bytes.
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
	p += 8
	offerBytes, rest, ok := cutLengthPrefixed(data[p:])
	if !ok {
		return nil, errors.New("resume material: truncated peer offer")
	}
	chosenBytes, rest, ok := cutLengthPrefixed(rest)
	if !ok {
		return nil, errors.New("resume material: truncated chosen set")
	}
	if len(rest) != realmBindingSize {
		return nil, errors.New("resume material: realm binding is not 5 bytes")
	}
	realm, err := decodeRealmBinding(rest)
	if err != nil {
		return nil, fmt.Errorf("resume material: realm binding: %w", err)
	}
	offer, err := aether.DecodeWireVersions(offerBytes)
	if err != nil {
		return nil, fmt.Errorf("resume material: peer offer: %w", err)
	}
	chosen, err := aether.DecodeNegotiatedWireVersions(chosenBytes)
	if err != nil {
		return nil, fmt.Errorf("resume material: chosen set: %w", err)
	}
	m.PeerOffer, m.Chosen = offer, chosen
	m.Realm = realm
	return m, nil
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
	// A resume reuses the original handshake's wire version set. When
	// choosing again from this transport's offer and the peer's recorded
	// offer does not give that set, the material is dropped and Dial runs the
	// full handshake, which negotiates the set this build chooses.
	if again, err := t.chooseWireVersions(m.PeerOffer); err != nil || !again.Equal(m.Chosen) {
		t.initiatorTickets.Evict(target.NodeID)
		return nil, nil
	}

	// Fresh ephemeral X25519 keypair for this resume — the forward-secret
	// input that makes the derived traffic keys unique to this resume, so no
	// (key,nonce) pair is ever shared with the original session.
	ephPriv, err := newResumeEphemeral()
	if err != nil {
		return nil, fmt.Errorf("resume: ephemeral keygen: %w", err)
	}
	ephIPub := ephPriv.PublicKey().Bytes()

	// Canonical PSK (initiator perspective: i2r=SendKey, r2i=RecvKey) plus the
	// PSK-only binder proving we actually hold the ticket keys.
	psk := canonicalResumePSK(m.SendKey, m.RecvKey)
	binder := resumeBinder(psk, m.Opaque, ephIPub)

	// Resume packet: [resumePrefix][2B opaqueLen][opaque][32B ephIPub][32B binder].
	pkt := make([]byte, 0, 1+2+len(m.Opaque)+resumeEphPubSize+resumeBinderSize)
	pkt = append(pkt, resumePrefix)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(m.Opaque)))
	pkt = append(pkt, lenBuf...)
	pkt = append(pkt, m.Opaque...)
	pkt = append(pkt, ephIPub...)
	pkt = append(pkt, binder...)

	if _, err := udp.WriteToUDP(pkt, remoteAddr); err != nil {
		return nil, fmt.Errorf("resume: write: %w", err)
	}

	// Wait for accept/reject. Accept carries the responder ephemeral and a
	// confirm-tag sealed under the freshly derived r→i key (proof the
	// responder derived the same keys); reject means fall back to a full
	// handshake.
	readBuf := make([]byte, 256)
	if err := udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	// SetReadDeadline fails only on a closed socket, which no later read can
	// use, so the clear's error is dropped.
	defer func() { _ = udp.SetReadDeadline(time.Time{}) }()
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
		// Accept: [resumeAcceptPrefix][32B ephRPub][16B confirmTag].
		if n != 1+resumeEphPubSize+resumeConfirmTagLen {
			return nil, fmt.Errorf("resume: bad accept length %d", n)
		}
		ephRPub := readBuf[1 : 1+resumeEphPubSize]
		confirmTag := readBuf[1+resumeEphPubSize : n]

		dh, err := resumeDH(ephPriv, ephRPub)
		if err != nil {
			return nil, fmt.Errorf("resume: dh: %w", err)
		}
		keyI2R, keyR2I := deriveResumeKeys(psk, dh, m.Opaque, ephIPub, ephRPub)

		// Initiator: send = i→r key, recv = r→i key.
		send, recv, err := buildResumeCipherStates(keyI2R, keyR2I)
		if err != nil {
			return nil, err
		}
		// The responder sealed the confirm-tag with keyR2I at nonce 0; open it
		// with recv (keyR2I nonce 0) to prove they derived identical keys.
		if _, err := recv.Decrypt(nil, nil, confirmTag); err != nil {
			return nil, fmt.Errorf("resume: confirm tag verify failed: %w", err)
		}
		// Resume confirmed — instantiate noiseConn with the fresh states.
		nc := newNoiseConnDial(udp, remoteAddr, target.NodeID, send, recv, t.maxPacket, t)
		nc.wireVersions, nc.peerWireVersions = m.Chosen, m.PeerOffer
		nc.realm = m.Realm
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
// path; the initiator's decrypt consumes cs2 nonce 0 on recv. Both then
// advance to nonce 1 for subsequent session traffic. The ticket snapshot
// (captured at nonce 0) is reused only as a PSK *input* — resume derives
// FRESH per-resume keys from it via ephemeral DH (session_resume_keys.go),
// so it never reinstalls the live session's advancing keys.
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
// resume attempts. runReader calls it for a datagram whose first byte is
// resumePrefix (which is not dialNoncePrefix). The packet layout is:
//
//	[1B prefix=0xFA][2B opaqueLen][opaque ticket][32B ephemeral X25519 pub][32B binder]
//
// Steps:
//  1. Parse the packet.
//  2. Decrypt the ticket with the transport's TicketStore (rotates
//     between current + previous keys) to recover the PSK.
//  3. Verify the PSK-possession binder (before the replay slot / DH work).
//  4. Reject if the ticket has been seen before (replay guard via
//     seenTickets cache keyed by ticket nonce).
//  5. Fresh X25519 exchange → forward-secret per-resume keys via
//     HKDF(PSK ‖ DH) (session_resume_keys.go).
//  6. On success: reply resumeAcceptPrefix + [ephemeral pub][confirm-tag].
//  7. On failure: send resumeRejectPrefix so the initiator evicts its
//     cached ticket and falls back to a full handshake.
func (l *noiseListener) handleResumePacket(ctx context.Context, conn *net.UDPConn, pkt []byte, addr *net.UDPAddr) {
	// Send-or-reject helper.
	sendReject := func() {
		_, _ = conn.WriteToUDP([]byte{resumeRejectPrefix}, addr)
	}

	if l.transport.ticketStore == nil {
		sendReject()
		return
	}
	// Resume packet: [prefix][2B opaqueLen][opaque][32B ephIPub][32B binder].
	if len(pkt) < 1+2+(ticketNonceSize+ticketTagSize)+resumeEphPubSize+resumeBinderSize {
		sendReject()
		return
	}
	opaqueLen := int(binary.BigEndian.Uint16(pkt[1:3]))
	if opaqueLen <= 0 || 3+opaqueLen+resumeEphPubSize+resumeBinderSize > len(pkt) {
		sendReject()
		return
	}
	off := 3
	opaque := pkt[off : off+opaqueLen]
	off += opaqueLen
	ephIPub := pkt[off : off+resumeEphPubSize]
	off += resumeEphPubSize
	binder := pkt[off : off+resumeBinderSize]

	ticket, err := l.transport.ticketStore.DecryptTicket(opaque)
	if err != nil {
		dbgNoise.Printf("resume: decrypt failed from %s: %v", addr, err)
		sendReject()
		return
	}

	// Canonical PSK from the responder's perspective (i2r=RecvKey, r2i=SendKey)
	// so it matches the initiator's canonicalResumePSK byte-for-byte.
	psk := canonicalResumePSK(ticket.RecvKey, ticket.SendKey)

	// Verify the PSK-possession binder BEFORE consuming the replay slot or
	// spending an X25519 op: a peer that holds a stolen opaque ticket but not
	// its keys can then neither burn a legitimate ticket's replay nonce nor
	// make us do DH work.
	if !resumeBinderValid(psk, opaque, ephIPub, binder) {
		dbgNoise.Printf("resume: binder invalid from %s", addr)
		sendReject()
		return
	}

	// The resumed session would run the set the original handshake chose.
	// When choosing again from this transport's current offer and the
	// initiator's recorded offer gives another set, or refuses, the resume is
	// rejected and the initiator's full handshake negotiates afresh.
	if again, err := l.transport.chooseWireVersions(ticket.PeerOffer); err != nil || !again.Equal(ticket.Chosen) {
		dbgNoise.Printf("resume: ticket's wire version set %v is not this build's choice for %s", ticket.Chosen, addr)
		sendReject()
		return
	}

	// Replay protection: reject if the same ticket nonce has already been
	// consumed. The first 12 bytes of the opaque blob (GCM nonce) are the cache
	// key — unique per IssueTicket call (96 bits of rand entropy).
	replayKey := opaque[:ticketNonceSize]
	if l.transport.seenTickets != nil {
		if !l.transport.seenTickets.MarkOrReject(replayKey, ticket.ExpiresAt) {
			dbgNoise.Printf("resume: replay detected from %s", addr)
			sendReject()
			return
		}
	}

	// Fresh ephemeral + DH → forward-secret, per-resume traffic keys.
	ephPriv, err := newResumeEphemeral()
	if err != nil {
		sendReject()
		return
	}
	ephRPub := ephPriv.PublicKey().Bytes()
	dh, err := resumeDH(ephPriv, ephIPub)
	if err != nil {
		dbgNoise.Printf("resume: dh failed from %s: %v", addr, err)
		sendReject()
		return
	}
	keyI2R, keyR2I := deriveResumeKeys(psk, dh, opaque, ephIPub, ephRPub)

	// Responder: send = r→i key (keyR2I), recv = i→r key (keyI2R).
	send, recv, err := buildResumeCipherStates(keyR2I, keyI2R)
	if err != nil {
		sendReject()
		return
	}

	// Accept: [resumeAcceptPrefix][32B ephRPub][16B confirmTag]. The confirm-tag
	// is an empty seal under keyR2I (nonce 0) proving we derived the same keys;
	// the initiator opens it with its recv (keyR2I nonce 0).
	confirmTag, err := send.Encrypt(nil, nil, nil)
	if err != nil {
		sendReject()
		return
	}
	reply := make([]byte, 0, 1+resumeEphPubSize+resumeConfirmTagLen)
	reply = append(reply, resumeAcceptPrefix)
	reply = append(reply, ephRPub...)
	reply = append(reply, confirmTag...)
	if _, err := conn.WriteToUDP(reply, addr); err != nil {
		dbgNoise.Printf("resume: write accept: %v", err)
		return
	}

	// Instantiate the resumed noiseConn and register it in the listener's
	// session table so subsequent packets route correctly.
	// remoteIdentity is nil here: the 0.5-RTT resume path authenticates the
	// peer via the ticket PSK + confirm-tag, not a signed NodeInfo, so no
	// verified ed25519 identity key is available to thread through.
	nc := newNoiseConnListener(l, send, recv, addr, ticket.PeerID, nil)
	// Restore the original session's scope from the ticket so the resumed
	// conn keeps its relay isolation: a conn registered scopeless ("") reads
	// as dedicated mode to resolveRelayTarget's cross-partition guard
	// (relay.go), which treats an empty scope as unrestricted.
	nc.scopeID = ticket.ScopeID
	nc.wireVersions, nc.peerWireVersions = ticket.Chosen, ticket.PeerOffer
	nc.realm = ticket.Realm
	key := addr.String()
	l.mu.Lock()
	l.sessions.Put(ticket.PeerID, key, ticket.ScopeID, &noiseConnSession{conn: nc, nodeID: ticket.PeerID})
	l.mu.Unlock()

	// Deliver to the incoming-session channel so the application layer
	// sees the resumed session just like any XK/XX-established one.
	s := aether.NewConnection(l.transport.localNode, ticket.PeerID, nc, aether.ProtoNoise)
	s.OnClose(func() { closeAbandoned(nc) })
	// The hand-off to Accept runs off this read loop (handOffSession): a wait
	// on a full Accept queue here would hold every datagram of the socket.
	go l.handOffSession(ctx.Done(), s, nc)
	dbgNoise.Printf("resume: accepted session with %s via 0.5-RTT ticket", ticket.PeerID.Short())
}

// buildResumeCipherStates instantiates flynn/noise CipherStates from a pair of
// resume traffic keys. Both perspectives call it (initiator and responder).
// Uses `UnsafeNewCipherState`, flynn/noise's documented helper for installing
// externally-derived keys. Nonce starts at 0 because the keys are FRESH per
// resume (see deriveResumeKeys) — never the original session's advancing keys —
// so nonce 0 here can never collide with the original session.
//
// The cipher suite must match what the original handshake used: aether
// hard-wires Curve25519 / ChaCha20-Poly1305 / BLAKE2b.
func buildResumeCipherStates(sendKey, recvKey [32]byte) (*fnoise.CipherState, *fnoise.CipherState, error) {
	cs := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashBLAKE2b)
	send := fnoise.UnsafeNewCipherState(cs, sendKey, 0)
	recv := fnoise.UnsafeNewCipherState(cs, recvKey, 0)
	if send == nil || recv == nil {
		return nil, nil, errors.New("resume: UnsafeNewCipherState returned nil")
	}
	return send, recv, nil
}
