//go:build !js

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
	"encoding/binary"
	"fmt"
	"net"
	"time"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	"github.com/flynn/noise"
)

func (t *NoiseTransport) performInitiatorHandshake(ctx context.Context, udpConn *net.UDPConn, path aether.Path) (aether.Connection, error) {
	return t.performInitiatorHandshakeAttempt(ctx, udpConn, path, false)
}

// performInitiatorHandshakeAttempt runs one handshake attempt. When
// `xxOnly` is true, the XK-cached-key fast path is bypassed even if a
// key is cached — the attempt forces XX. This lets the XK failure path
// retry exactly once, on XX, without recursing back into itself (which
// was formerly possible if evictPeerKey raced with another cacher).
func (t *NoiseTransport) performInitiatorHandshakeAttempt(ctx context.Context, udpConn *net.UDPConn, path aether.Path, xxOnly bool) (aether.Connection, error) {
	dbgHandshake.Printf("Starting initiator handshake to %s (xxOnly=%v)", path.NodeID.Short(), xxOnly)

	// Determine active key and scope context.
	// If a dial override is present (SharedTransport), use the scope's keys
	// and prepend a preamble. Otherwise use the transport's own keys.
	var activeKey []byte
	var preambleTenantID string
	if override := getDialOverride(ctx); override != nil && len(override.Keys) > 0 {
		activeKey = override.Keys[0]
		preambleTenantID = override.ScopeID
		dbgHandshake.Printf("Using dial override for scope %q", preambleTenantID)
	} else {
		activeKey = t.keyManager.ActiveKey()
	}
	fingerprint := transportCrypto.CRC32Hash(activeKey)

	// Check peer key cache — use XK if we have the responder's static key,
	// fall back to XX for first contact or after key eviction. Retries
	// force-XX via xxOnly to avoid recursing back into a stale-key loop.
	var cachedPeerKey []byte
	if !xxOnly {
		cachedPeerKey = t.lookupPeerKey(path.NodeID)
	}
	pattern := noise.HandshakeXX
	if cachedPeerKey != nil {
		pattern = noise.HandshakeXK
		dbgHandshake.Printf("Using XK handshake (cached peer key for %s)", path.NodeID.Short())
	} else {
		dbgHandshake.Printf("Using XX handshake (no cached key for %s)", path.NodeID.Short())
	}

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hsCfg := noise.Config{
		Pattern:     pattern,
		Initiator:   true,
		Prologue:    activeKey,
		CipherSuite: suite,
		StaticKeypair: noise.DHKey{
			Private: append([]byte(nil), t.staticPriv...),
			Public:  append([]byte(nil), t.staticPub...),
		},
		Random: rand.Reader,
	}
	if cachedPeerKey != nil {
		hsCfg.PeerStatic = append([]byte(nil), cachedPeerKey...)
	}
	hs, err := noise.NewHandshakeState(hsCfg)
	if err != nil {
		dbgHandshake.Printf("Failed to create handshake state: %v", err)
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		dbgHandshake.Printf("Failed to write message 1: %v", err)
		return nil, err
	}

	// Build packet: [optional preamble][CRC32 fingerprint][pattern flag][noise msg1]
	fpBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fpBuf, fingerprint)
	var patFlag byte = patternFlagXX
	if cachedPeerKey != nil {
		patFlag = patternFlagXK
	}

	var packet []byte
	if preambleTenantID != "" {
		preamble, pErr := EncodePreamble(preambleTenantID)
		if pErr != nil {
			return nil, pErr
		}
		packet = make([]byte, 0, len(preamble)+5+len(msg1))
		packet = append(packet, preamble...)
		packet = append(packet, fpBuf...)
		packet = append(packet, patFlag)
		packet = append(packet, msg1...)
	} else {
		packet = make([]byte, 5+len(msg1))
		copy(packet[:4], fpBuf)
		packet[4] = patFlag
		copy(packet[5:], msg1)
	}

	if _, err = udpConn.Write(packet); err != nil {
		dbgHandshake.Printf("Failed to send message 1: %v", err)
		return nil, err
	}
	dbgHandshake.Printf("Sent message 1 (fingerprint: %x, preamble: %v, pattern: %s)", fingerprint, preambleTenantID != "", pattern.Name)

	deadline := t.handshakeDeadline(ctx)
	if err := udpConn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	buf := make([]byte, t.maxPacket)

	// msg1/msg2 retransmit loop: on raw UDP, a single dropped datagram
	// fails the whole handshake (was H-Handshake-Retx). Retry msg1 every
	// initiatorRetryInterval until either msg2 arrives, the per-attempt
	// deadline fires, or the caller's ctx cancels. Each retry uses the
	// same handshake packet — Noise XX/XK msg1 carries no nonce so
	// receiver-side dedup is the responder's responsibility (it tolerates
	// duplicates by ignoring msg1 after it's started building msg2).
	n, err := readWithMsg1Retry(udpConn, packet, buf, deadline)
	if err != nil {
		// If XK failed (peer key rotated), evict cache and retry with XX
		if cachedPeerKey != nil {
			dbgHandshake.Printf("XK handshake failed with %s, evicting cache and retrying XX: %v", path.NodeID.Short(), err)
			t.evictPeerKey(path.NodeID)
			return t.performInitiatorHandshakeAttempt(ctx, udpConn, path, true /* xxOnly */)
		}
		dbgHandshake.Printf("Failed to receive message 2: %v", err)
		return nil, fmt.Errorf("%w: %v", aether.ErrHandshakeFailed, err)
	}
	dbgHandshake.Printf("Received message 2 (%d bytes)", n)

	// Response does not have fingerprint
	payload, _, _, err := hs.ReadMessage(nil, buf[:n])
	if err != nil {
		// XK decryption failure = stale cached key. Evict and retry XX.
		if cachedPeerKey != nil {
			dbgHandshake.Printf("XK msg2 decrypt failed with %s, evicting cache and retrying XX: %v", path.NodeID.Short(), err)
			t.evictPeerKey(path.NodeID)
			return t.performInitiatorHandshakeAttempt(ctx, udpConn, path, true /* xxOnly */)
		}
		dbgHandshake.Printf("Failed to read message 2: %v", err)
		return nil, fmt.Errorf("%w: %v", aether.ErrHandshakeFailed, err)
	}
	remoteNode, _, remoteCaps, remoteMaxAckDelayUS, err := t.verifyNodeInfo(hs.PeerStatic(), payload, path.NodeID)
	if err != nil {
		dbgHandshake.Printf("Failed to verify remote node: %v", err)
		return nil, fmt.Errorf("%w: %v", aether.ErrHandshakeFailed, err)
	}
	dbgHandshake.Printf("Verified remote node: %s", remoteNode.Short())

	// Cache the peer's static key for future XK reconnections
	t.cachePeerKey(remoteNode, hs.PeerStatic())

	nodePayload, err := t.encodeNodeInfo()
	if err != nil {
		return nil, err
	}
	msg3, sendCS, recvCS, err := hs.WriteMessage(nil, nodePayload)
	if err != nil {
		dbgHandshake.Printf("Failed to write message 3: %v", err)
		return nil, err
	}
	if _, err = udpConn.Write(msg3); err != nil {
		dbgHandshake.Printf("Failed to send message 3: %v", err)
		return nil, err
	}
	dbgHandshake.Printf("Handshake complete with %s (pattern: %s)", remoteNode.Short(), pattern.Name)
	_ = udpConn.SetReadDeadline(time.Time{})
	nc := newNoiseConnDial(udpConn, path.Address, remoteNode, sendCS, recvCS, t.maxPacket, t)
	nc.scopeID = preambleTenantID
	nc.peerMaxAckDelay = decodeMaxAckDelay(remoteMaxAckDelayUS)

	// Negotiate explicit nonce mode if both sides support it
	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
		dbgHandshake.Printf("Explicit nonce mode enabled with %s", remoteNode.Short())
	}

	// Register outgoing session
	t.outgoingMu.Lock()
	t.outgoingSessions[string(remoteNode)] = nc
	t.outgoingMu.Unlock()

	// Ensure cleanup on close
	originalStop := nc.parentStop
	nc.parentStop = func() {
		t.outgoingMu.Lock()
		delete(t.outgoingSessions, string(remoteNode))
		t.outgoingMu.Unlock()
		originalStop()
	}

	go nc.runReader()
	s := aether.NewConnection(t.localNode, remoteNode, nc, aether.ProtoNoise)
	s.OnClose(func() { nc.Close() })
	return s, nil
}

// performInitiatorHandshakeShared performs a Noise handshake using the listener's
// shared UDP socket. Handshake responses are received via the listener's
// pendingDials channel dispatch. After completion, the session is registered
// in the listener's session map for ongoing packet dispatch.
func (t *NoiseTransport) performInitiatorHandshakeShared(ctx context.Context, listener *noiseListener, addr *net.UDPAddr, path aether.Path, crossOrgPreamble bool) (aether.Connection, error) {
	return t.performInitiatorHandshakeSharedAttempt(ctx, listener, addr, path, false, crossOrgPreamble)
}

// performInitiatorHandshakeSharedAttempt runs one shared-socket handshake
// attempt. `xxOnly` forces XX even if a peer key is cached — used by the
// XK-failure retry to bound recursion depth to 1 (preventing a stale-key
// loop if another goroutine re-caches the peer key during eviction).
// `crossOrgPreamble` prepends a routing preamble to msg1/retransmits/msg3
// so the cross-org anycast-receiving machine can hairpin to the target.
func (t *NoiseTransport) performInitiatorHandshakeSharedAttempt(ctx context.Context, listener *noiseListener, addr *net.UDPAddr, path aether.Path, xxOnly bool, crossOrgPreamble bool) (aether.Connection, error) {
	dbgHandshake.Printf("Starting shared-socket handshake to %s (xxOnly=%v)", path.NodeID.Short(), xxOnly)

	// Register pending dial with a unique nonce so the responder can echo it back
	nonce, responseCh := listener.registerPendingDial()
	defer listener.unregisterPendingDial(nonce)

	// Key selection (same as performInitiatorHandshake)
	var activeKey []byte
	var preambleTenantID string
	if override := getDialOverride(ctx); override != nil && len(override.Keys) > 0 {
		activeKey = override.Keys[0]
		preambleTenantID = override.ScopeID
	} else {
		activeKey = t.keyManager.ActiveKey()
	}
	fingerprint := transportCrypto.CRC32Hash(activeKey)

	// Check peer key cache — use XK if available, XX otherwise. The XX-only
	// retry path bypasses the cache so we don't re-enter the same failure.
	var cachedPeerKey []byte
	if !xxOnly {
		cachedPeerKey = t.lookupPeerKey(path.NodeID)
	}
	pattern := noise.HandshakeXX
	if cachedPeerKey != nil {
		pattern = noise.HandshakeXK
		dbgHandshake.Printf("Shared-socket: using XK (cached peer key for %s)", path.NodeID.Short())
	}

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hsCfg := noise.Config{
		Pattern:     pattern,
		Initiator:   true,
		Prologue:    activeKey,
		CipherSuite: suite,
		StaticKeypair: noise.DHKey{
			Private: append([]byte(nil), t.staticPriv...),
			Public:  append([]byte(nil), t.staticPub...),
		},
		Random: rand.Reader,
	}
	if cachedPeerKey != nil {
		hsCfg.PeerStatic = append([]byte(nil), cachedPeerKey...)
	}
	hs, err := noise.NewHandshakeState(hsCfg)
	if err != nil {
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}

	// Build packet: [CRC32 fingerprint][pattern flag][noise msg1]
	fpBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fpBuf, fingerprint)
	var patFlag byte = patternFlagXX
	if cachedPeerKey != nil {
		patFlag = patternFlagXK
	}
	var packet []byte
	if preambleTenantID != "" {
		preamble, pErr := EncodePreamble(preambleTenantID)
		if pErr != nil {
			return nil, pErr
		}
		packet = make([]byte, 0, len(preamble)+5+len(msg1))
		packet = append(packet, preamble...)
		packet = append(packet, fpBuf...)
		packet = append(packet, patFlag)
		packet = append(packet, msg1...)
	} else {
		packet = make([]byte, 5+len(msg1))
		copy(packet[:4], fpBuf)
		packet[4] = patFlag
		copy(packet[5:], msg1)
	}

	// Prepend dial nonce so the responder can echo it back for routing
	noncePacket := make([]byte, 0, 1+dialNonceLen+len(packet))
	noncePacket = append(noncePacket, dialNoncePrefix)
	noncePacket = append(noncePacket, nonce...)
	noncePacket = append(noncePacket, packet...)

	// Cross-org dials prepend a routing preamble OUTSIDE the dial-nonce
	// envelope. The anycast-receiving machine (M_r) strips the preamble
	// before forwarding; the target machine (M_t) then sees the
	// dial-nonce envelope exactly as a direct dial would have produced.
	if crossOrgPreamble {
		preamble := EncodeRoutingPreamble(path.NodeID)
		framed := make([]byte, 0, len(preamble)+len(noncePacket))
		framed = append(framed, preamble...)
		framed = append(framed, noncePacket...)
		noncePacket = framed
	}

	// currentMsg1 is the exact packet retransmitted while we wait for
	// msg2 — initially the plain msg1 envelope, swapped for the
	// cookie-wrapped form once we've answered a source-validation retry.
	currentMsg1 := noncePacket

	// Send msg1 via correct socket (IPv4 or IPv6 based on target)
	if _, err = listener.connFor(addr).WriteToUDP(currentMsg1, addr); err != nil {
		return nil, fmt.Errorf("handshake msg1: %w", err)
	}

	// Receive msg2 via pending dial channel. The responder may instead
	// reply with a RETRY packet (S3 — _SECURITY.md §3.1) to validate our
	// source address. Detect that, then re-send msg1 with the cookie
	// prepended. We accept at most one retry round-trip per handshake.
	//
	// Retransmit msg1 on a ticker until msg2 arrives or the dial deadline
	// elapses: raw UDP drops packets, and on a cross-org / public path
	// there is no 6PN reliability underneath. The responder re-sends its
	// cached msg2 when it sees a duplicate msg1, so this single ticker
	// recovers a lost msg1 OR a lost msg2.
	deadline := t.handshakeDeadline(ctx)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	rxmit := time.NewTicker(handshakeRetransmitInterval)
	defer rxmit.Stop()
	var msg2 []byte
	retried := false
recvLoop:
	for {
		select {
		case resp := <-responseCh:
			if HasRetryPrefix(resp) && len(resp) <= retryHeaderSize {
				// A bare RETRY token is exactly retryHeaderSize bytes and
				// begins with retryPrefix. A real msg2 can also begin with
				// retryPrefix by chance (Noise fingerprints span all bytes)
				// but carries a signed NodeInfo (~360-420B), so the
				// exact-length test separates them with no HMAC check here.
				if retried {
					// Duplicate/stale RETRY: the responder mints a fresh cookie
					// per plain-msg1 retransmit, so on a lossy 6PN path two can
					// be in flight. The first cookie stays valid for
					// RetryTokenTTL and the cookie-bearing msg1 retransmit draws
					// the real msg2, so a second cookie must be dropped, never
					// read as msg2 (its 49 bytes fail the Noise s-token length
					// check as message-too-short).
					continue
				}
				// Truncated/garbage retry-shaped packet: keep waiting for a
				// well-formed token (also guards the slice below).
				if len(resp) < retryHeaderSize {
					continue
				}
				cookie := resp[:retryHeaderSize]
				// Rebuild msg1 with the cookie prepended INSIDE the
				// dial-nonce envelope so listener routing still works.
				wrapped := make([]byte, 0, 1+dialNonceLen+len(cookie)+len(packet))
				wrapped = append(wrapped, dialNoncePrefix)
				wrapped = append(wrapped, nonce...)
				wrapped = append(wrapped, cookie...)
				wrapped = append(wrapped, packet...)
				// Cross-org: the cookie was minted by M_t and signed with
				// M_t's per-process retry secret. The retransmit MUST land
				// back on M_t for validation — the routing preamble is the
				// only way to ensure that. Without this, the initiator's
				// retransmit lands on whichever same-org machine wins the
				// 5-tuple hash; if it's not M_t, validation fails and the
				// dial stalls until timeout.
				if crossOrgPreamble {
					preamble := EncodeRoutingPreamble(path.NodeID)
					framed := make([]byte, 0, len(preamble)+len(wrapped))
					framed = append(framed, preamble...)
					framed = append(framed, wrapped...)
					wrapped = framed
				}
				if _, err = listener.connFor(addr).WriteToUDP(wrapped, addr); err != nil {
					return nil, fmt.Errorf("handshake msg1 retry: %w", err)
				}
				currentMsg1 = wrapped // retransmits now carry the cookie
				retried = true
				continue
			}
			// Observability: identify anything mistaken for msg2. A real XX msg2
			// carries the signed NodeInfo (~360-420B); anything materially
			// shorter reaching ReadMessage yields flynn/noise's opaque
			// "message is too short" with no clue what the packet WAS. The
			// retry-shaped filter above only catches retryPrefix+<=49, so this
			// records first-byte+length for any other short arrival.
			if len(resp) > 0 && len(resp) < 96 {
				dbgHandshake.Printf("shared-socket: SHORT %dB packet (first=0x%02X) accepted as msg2 from %s — ReadMessage will likely fail", len(resp), resp[0], addr)
			}
			msg2 = resp
			break recvLoop
		case <-rxmit.C:
			// Re-send msg1. The responder treats a duplicate msg1 as a
			// request to re-send msg2 (see handleHandshake), so this is
			// safe and idempotent.
			if _, werr := listener.connFor(addr).WriteToUDP(currentMsg1, addr); werr != nil {
				return nil, fmt.Errorf("handshake msg1 retransmit: %w", werr)
			}
		case <-timer.C:
			return nil, fmt.Errorf("%w: msg2 timeout", aether.ErrHandshakeFailed)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	dbgHandshake.Printf("Shared-socket msg2 received: %d bytes", len(msg2))
	payload, _, _, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		// XK failure — evict stale key and retry with XX
		if cachedPeerKey != nil {
			dbgHandshake.Printf("XK shared-socket msg2 failed with %s, evicting and retrying XX: %v", path.NodeID.Short(), err)
			t.evictPeerKey(path.NodeID)
			listener.unregisterPendingDial(nonce)
			return t.performInitiatorHandshakeSharedAttempt(ctx, listener, addr, path, true /* xxOnly */, crossOrgPreamble)
		}
		return nil, fmt.Errorf("%w: msg2 read: %v", aether.ErrHandshakeFailed, err)
	}
	remoteNode, remoteIdentity, remoteCaps, remoteMaxAckDelayUS, err := t.verifyNodeInfo(hs.PeerStatic(), payload, path.NodeID)
	if err != nil {
		return nil, fmt.Errorf("%w: verify: %v", aether.ErrHandshakeFailed, err)
	}

	// Cache the peer's static key for future XK reconnections
	t.cachePeerKey(remoteNode, hs.PeerStatic())

	nodePayload, err := t.encodeNodeInfo()
	if err != nil {
		return nil, err
	}
	msg3, sendCS, recvCS, err := hs.WriteMessage(nil, nodePayload)
	if err != nil {
		return nil, err
	}
	// Cross-org: msg3 also carries the routing preamble so any same-org
	// machine receiving it (Fly's 5-tuple hash could land us on a
	// different machine than msg1 in edge cases) can hairpin to M_t. The
	// preamble is OUTSIDE the noise frame; M_r strips before forwarding.
	// Post-handshake data packets rely on Fly's edge flow stickiness —
	// if that proves insufficient in production we revisit and add a
	// persistent preamble-on-every-write path.
	// Wrap msg3 in the dial-nonce envelope, exactly as msg1 already is.
	//
	// msg3 was the ONLY handshake message sent as raw Noise ciphertext, and a
	// ciphertext's first byte is uniformly random. The responder classifies
	// inbound packets by that first byte (ClassifyPacket), and the QUIC range
	// 0x40-0xBF is 128 of 256 values — so ~50% of raw msg3s were classified as
	// QUIC and handed to DeliverQUICPacket, which enqueues them for quic-go
	// with no validation whatsoever. quic-go discards them and the msg3 is
	// gone. Not packet loss: a systematic 50% misroute at the receiver.
	//
	// The consequence was the fleet-wide noise-UDP sawtooth. A swallowed msg3
	// leaves the session HALF-OPEN — the initiator holds cipher states and
	// believes it is connected while the responder never completes and prunes
	// at 30s — so nothing ever comes back and STALL-DETECT reaps the session
	// at 120s with "no forward progress". Links established, won the path,
	// died ~2m later, and reformed, forever.
	//
	// Byte-range classification cannot separate ciphertext from QUIC — the
	// ranges overlap by construction and no amount of tightening fixes a
	// uniformly random byte. The envelope removes the ambiguity instead of
	// narrowing it: dialNoncePrefix is checked BEFORE the QUIC range, so an
	// enveloped msg3 routes as PacketDial 100% of the time. This is the same
	// reason msg1 and msg2 were never affected — both already carry it.
	msg3Wire := wrapDialResponse(nonce, msg3)
	if crossOrgPreamble {
		preamble := EncodeRoutingPreamble(path.NodeID)
		msg3Wire = make([]byte, 0, len(preamble)+len(msg3))
		msg3Wire = append(msg3Wire, preamble...)
		msg3Wire = append(msg3Wire, msg3...)
	}
	if _, err = listener.connFor(addr).WriteToUDP(msg3Wire, addr); err != nil {
		return nil, fmt.Errorf("handshake msg3: %w", err)
	}

	dbgHandshake.Printf("Shared-socket handshake complete with %s (pattern: %s)", remoteNode.Short(), pattern.Name)

	// Create session using the listener's shared socket (like listener-accepted sessions)
	nc := newNoiseConnListener(listener, sendCS, recvCS, addr, remoteNode, remoteIdentity)
	nc.scopeID = preambleTenantID
	nc.peerMaxAckDelay = decodeMaxAckDelay(remoteMaxAckDelayUS)
	// Cross-org: persist the preamble target on the noiseConn so the
	// writeFunc continues to prepend it on every post-handshake send.
	// Without this, data packets from initiator → cross-org peer land
	// on whichever same-org machine wins Fly's 5-tuple hash and there's
	// no session there — they get dropped silently.
	if crossOrgPreamble {
		nc.crossOrgPreambleTarget = path.NodeID
	}

	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
	}

	// msg3 is the only message in this 3-message handshake with no loss
	// protection, and it runs over lossy UDP: msg1 has a retransmit ticker
	// (handshakeRetransmitInterval) and msg2 is re-sent from hs.response on any
	// duplicate msg1 — msg3 was written once and never confirmed. A single
	// dropped msg3 leaves the session HALF-OPEN: we hold cipher states and
	// believe we are connected, while the responder never completes and prunes
	// its listenerHandshake at the 30s TTL. Everything we send then lands on a
	// responder with no session for this addr and is discarded, nothing ever
	// comes back, and STALL-DETECT reaps us at the 120s threshold with
	// "session stuck (no forward progress)" / "ping timeout (no inbound
	// activity)". Fleet-wide that is the noise-UDP sawtooth: links establish,
	// win the path, die ~2m later, reform, forever.
	//
	// Retransmit until the peer proves it completed by sending us anything.
	// Safe and idempotent: the responder ignores a duplicate msg3 once its
	// handshake is complete, and any inbound packet at all stops the loop.
	go retransmitMsg3UntilActive(listener, addr, msg3Wire, nc)

	// Simultaneous-dial deterministic tiebreak (initiator side). See the
	// responder-side comment in handleHandshake for the full rationale —
	// both peers concurrently dialing each other land at the same map
	// key on each side, and without coordinated dedup at the noise
	// layer the displaced session gets orphaned and produces a stalled
	// conversation that the upper layer can't see.
	//
	// Rule mirrored from the responder: keep the session where the
	// lower-NodeID peer is the initiator. As initiator here we keep
	// this session only if our NodeID is LOWER than the peer's. If we
	// are higher, the peer's outbound (their initiator) is the
	// preferred conversation and our outbound is closed.
	//
	// Skipped when no existing session is registered for this NodeID —
	// first-time dials install unconditionally.
	if existing := listener.sessions.Get(remoteNode); existing != nil {
		// AER-004 (initiator mirror): only yield to an existing session that
		// is actually alive. A dead session left by a restarted peer must not
		// veto this freshly-completed outbound, or the dial "succeeds" onto a
		// corpse and churns.
		existingConn := connFromSession(existing)
		existingDead := existingConn == nil || existingConn.IsClosed()
		localLower := string(t.localNode) < string(remoteNode)
		if !existingDead && !localLower {
			// Existing inbound is alive and is the preferred conversation.
			// Close this outbound loser.
			dbgHandshake.Printf("simultaneous-dial: closing outbound to %s (local %s >= remote, existing alive)",
				remoteNode.Short(), t.localNode.Short())
			nc.Close()
			return nil, aether.WrapOp("dial", aether.ProtoNoise, remoteNode,
				fmt.Errorf("simultaneous-dial: local NodeID is the preferred responder; existing inbound wins"))
		}
		// Either the existing session is dead, or we are the lower NodeID:
		// this outbound wins. Close the displaced/dead existing asynchronously.
		dbgHandshake.Printf("simultaneous-dial: displacing existing inbound for %s (dead=%v, local %s)",
			remoteNode.Short(), existingDead, t.localNode.Short())
		go existing.Close()
	}

	// Register in listener's session map so subsequent packets are dispatched correctly
	listener.registerDialSession(addr, nc, remoteNode)

	// No separate runReader — the listener's run() loop handles all incoming packets
	s := aether.NewConnection(t.localNode, remoteNode, nc, aether.ProtoNoise)
	s.OnClose(func() { nc.Close() })
	return s, nil
}

// handshakeRetransmitInterval is how often the initiator re-sends msg1
// while still waiting for msg2. The Noise handshake runs over raw UDP,
// which drops packets — and on cross-org / public-internet paths there
// is no 6PN reliability underneath. Without retransmission a single lost
// msg1 or msg2 fails the whole handshake. Sized at a few × a typical
// cross-region RTT: long enough not to duplicate-storm a slow path,
// short enough for several attempts inside the dial deadline (~5s in
// mesh use). This is the same loss-recovery scheme WireGuard, QUIC and
// DTLS use for their handshakes.
const handshakeRetransmitInterval = 700 * time.Millisecond

// acceptHandoffTimeout bounds how long a completed handshake/resume waits to
// hand its session to a slow Accept consumer before dropping it. The handoff
// runs off the readLoop (AER-019) so this never stalls packet dispatch.
const acceptHandoffTimeout = 1 * time.Second

// msg3RetransmitWindow bounds how long the initiator keeps re-sending msg3
// while waiting for the peer's first inbound packet. It must comfortably exceed
// a few RTTs plus the responder's own msg2 retransmit handling, yet stay well
// under the 120s STALL-DETECT threshold so a genuinely unreachable peer fails
// fast rather than holding a doomed session open. Bounded by design: the loop
// also exits the instant any inbound activity arrives, and on session close.
const msg3RetransmitWindow = 10 * time.Second

// retransmitMsg3UntilActive re-sends msg3 on handshakeRetransmitInterval until
// the peer sends us anything (proving it completed the handshake), the session
// closes, or msg3RetransmitWindow expires.
//
// Without this, one dropped msg3 is unrecoverable: the initiator has cipher
// states and a live session, the responder has neither and prunes its pending
// handshake at 30s. The session then makes no forward progress in either
// direction and STALL-DETECT closes it at 120s — see
// handshake_msg3_retransmit_test.go.
//
// Any inbound packet is sufficient proof: the peer cannot decrypt or ACK
// anything on this session without having processed msg3.
func retransmitMsg3UntilActive(l *noiseListener, addr *net.UDPAddr, msg3Wire []byte, nc *noiseConn) {
	start := time.Now()
	deadline := start.Add(msg3RetransmitWindow)
	ticker := time.NewTicker(handshakeRetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-nc.closed:
			return
		case <-ticker.C:
			if nc.health.LastActivity().After(start) {
				return // peer answered — handshake demonstrably completed
			}
			if time.Now().After(deadline) {
				dbgHandshake.Printf("msg3 retransmit window expired for %s — peer never answered; "+
					"session will be reaped by STALL-DETECT", addr)
				return
			}
			if _, err := l.connFor(addr).WriteToUDP(msg3Wire, addr); err != nil {
				return // socket gone; nothing useful left to do
			}
			dbgHandshake.Printf("Retransmitting msg3 to %s (no inbound yet)", addr)
		}
	}
}

func (t *NoiseTransport) handshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(t.handshake)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return deadline
}

// Capability bitmask flags exchanged during handshake.
const (
	capExplicitNonce uint32 = 1 << 0 // Supports explicit-nonce mode (sliding window)
	// capSessionTicket (1 << 1) defined in session_ticket.go
)

// Handshake pattern flags — 1 byte after CRC32 fingerprint in msg1.
const (
	patternFlagXX byte = 0x00 // Noise XX (no pre-shared static key)
	patternFlagXK byte = 0x01 // Noise XK (initiator has responder's static key)
)

// encodeNodeInfo returns the signed NodeInfo payload advertised in the
// handshake. AE-P-20: the payload is constant for the transport's lifetime
// (identity key, caps, and advertised max_ack_delay are all fixed after
// construction — ticketStore is assigned once in NewNoiseTransport and never
// mutated), yet the responder previously recomputed a fresh ed25519.Sign +
// json.Marshal on EVERY inbound msg1 while holding the listener-wide l.mu on
// the single read-loop goroutine. Memoize it once so first-contact
// handshakes reuse the cached bytes instead of re-signing per handshake.
// Callers MUST treat the returned slice as read-only — it is shared across
// handshakes; every caller passes it as the read-only plaintext argument to
// state.WriteMessage, which never mutates it.
func (t *NoiseTransport) encodeNodeInfo() ([]byte, error) {
	t.nodeInfoOnce.Do(func() {
		caps := capExplicitNonce
		if t.ticketStore != nil {
			caps |= capSessionTicket
		}
		t.nodeInfoBytes, t.nodeInfoErr = t.identity.EncodeNodeInfo(caps, t.initialMaxAckDelayUS())
	})
	return t.nodeInfoBytes, t.nodeInfoErr
}

// initialMaxAckDelayUS returns the sender's advertised max_ack_delay (RFC
// 9002 §6.2) in microseconds, to be stamped into the outbound handshake
// NodeInfo payload. At handshake time there's no SRTT measurement yet —
// the receiver-side approximation max(ACKPolicy.MaxDelay, SRTT/4)
// degenerates to ACKPolicy.MaxDelay alone. Both initiator and responder
// stamp this same value so each peer's TLP can seed its PTO with the
// other's actual policy instead of the conservative 25ms default.
//
// Returns 0 if the policy MaxDelay is zero or negative (treated as
// "not advertised"); receivers fall back to their local approximation.
func (t *NoiseTransport) initialMaxAckDelayUS() uint32 {
	d := reliabilityACKPolicyMaxDelay
	if d <= 0 {
		return 0
	}
	us := d.Microseconds()
	if us <= 0 {
		return 0
	}
	if us > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(us)
}

// reliabilityACKPolicyMaxDelay mirrors reliability.DefaultACKPolicy().MaxDelay
// without importing the reliability package (which would be a layering
// inversion — reliability already imports aether's core types). 25ms
// matches the QUIC default and is the receiver-side policy that
// NoiseSession's ACKEngine emits ACKs against — advertising it as our
// max_ack_delay tells the peer's TLP not to PTO faster than our ACK pacing.
const reliabilityACKPolicyMaxDelay = 25 * time.Millisecond

// decodeMaxAckDelay converts the wire-format uint32 microseconds field
// into a time.Duration. Zero means "peer did not advertise" — callers
// fall back to the receiver-side approximation in that case.
func decodeMaxAckDelay(us uint32) time.Duration {
	if us == 0 {
		return 0
	}
	return time.Duration(us) * time.Microsecond
}

func (t *NoiseTransport) verifyNodeInfo(peerStatic []byte, payload []byte, expected aether.NodeID) (aether.NodeID, ed25519.PublicKey, uint32, uint32, error) {
	return transportCrypto.VerifyNodeInfo(peerStatic, payload, expected)
}

type listenerHandshake struct {
	state     *noise.HandshakeState
	created   time.Time
	responded bool
	// response is the RAW msg2 — never the nonce-wrapped bytes. This entry is
	// keyed by ADDRESS and lives for the prune TTL, so a later msg1 from the
	// same peer may belong to a different dial with a different nonce; the
	// nonce is therefore applied per-send by wrapDialResponse, not cached.
	response []byte
	scopeID  string // Extracted from preamble (empty for dedicated transports)
	// dialNonce is the nonce of the dial that CREATED this entry. Kept for
	// diagnostics only — never use it to answer a later msg1, which may carry
	// a newer nonce (see currentDialNonce).
	dialNonce []byte
}

// currentDialNonce returns the dial nonce carried by an inbound handshake
// packet, or nil when it is not nonce-tagged. Always read fresh from the packet
// being answered: the nonce identifies the DIAL, while listenerHandshake is
// keyed by ADDRESS and outlives any single dial.
func currentDialNonce(msg []byte) []byte {
	if len(msg) > 1+dialNonceLen && msg[0] == dialNoncePrefix {
		return msg[1 : 1+dialNonceLen]
	}
	return nil
}

// wrapDialResponse tags a responder reply with the initiator's dial nonce so
// dispatchToPendingDial can route it to the waiting dial. A nil nonce means the
// initiator did not tag its msg1, so the reply goes back bare.
func wrapDialResponse(dialNonce, response []byte) []byte {
	if dialNonce == nil {
		return response
	}
	out := make([]byte, 0, 1+dialNonceLen+len(response))
	out = append(out, dialNoncePrefix)
	out = append(out, dialNonce...)
	out = append(out, response...)
	return out
}

// isTrustedNoAmplifySource reports whether a msg1 source is on a trusted
// private network where the anti-amplification RETRY cookie is unnecessary —
// and actively harmful.
//
// The RETRY cookie defends ONLY against a spoofed source IP causing the
// responder to amplify a large msg2 toward a victim. On Fly, same-org peers
// reach each other over the 6PN, an IPv6 ULA (fdaa:…), and the platform
// enforces 6PN source addresses so they cannot be spoofed across the private
// network — the attack the cookie prevents is impossible there. Meanwhile the
// cookie is bound to the responder PROCESS's per-process secret plus the source
// IP, so for a same-org multi-machine app (two machines sharing one mesh
// identity) the msg1+cookie retransmit can land on a different machine that
// rejects the cookie, stranding every dial at msg2 timeout. Skipping the RETRY
// for a ULA source removes that failure mode and a round-trip, with no
// amplification exposure.
//
// Restricted to genuine IPv6 ULA (To4()==nil so a v4-mapped address can't slip
// through): a public/global source still gets the RETRY.
func isTrustedNoAmplifySource(addr *net.UDPAddr) bool {
	return addr != nil && addr.IP != nil && addr.IP.To4() == nil && addr.IP.IsPrivate()
}

func (l *noiseListener) handleHandshake(ctx context.Context, key string, addr *net.UDPAddr, msg []byte) {
	l.mu.Lock()
	hs := l.handshakes[key]

	// AER-005: a nonce-tagged packet from this address whose dial nonce
	// differs from the stored handshake's is a NEW dial. The initiator drops
	// its nonce and re-dials with a fresh one the moment a dial times out
	// (one lost msg2 is enough) or when the XK→XX fallback fires. The stale
	// entry's cached msg2 is bound to the OLD dial's ephemeral, so answering
	// the new msg1 with it fails the initiator's msg2-read every time until
	// the 30s TTL prune — stranding every re-dial from this peer for up to
	// ~45s. Drop the stale entry and treat this as a fresh handshake.
	if hs != nil {
		if incoming := currentDialNonce(msg); incoming != nil && hs.dialNonce != nil &&
			!bytes.Equal(incoming, hs.dialNonce) {
			dbgHandshake.Printf("re-dial from %s with fresh nonce %x (was %x): resetting stale handshake",
				addr, incoming, hs.dialNonce)
			delete(l.handshakes, key)
			hs = nil
		}
	}

	// New handshake initiation
	if hs == nil {
		// Check for dial nonce prefix (0xFD + 8-byte nonce) FIRST so the
		// retry path can route its response back through the same envelope.
		var dialNonce []byte
		innerMsg := msg
		if len(msg) > 1+dialNonceLen && msg[0] == dialNoncePrefix {
			dialNonce = make([]byte, dialNonceLen)
			copy(dialNonce, msg[1:1+dialNonceLen])
			innerMsg = msg[1+dialNonceLen:]
			dbgNoise.Printf("Received nonce-tagged handshake from %s (nonce: %x)", addr, dialNonce)
		}

		// Source-validation retry token (S3 — _SECURITY.md §3.1).
		// If the inner packet starts with retryPrefix, validate the cookie
		// and strip it; invalid cookies are silently dropped (no response
		// = no amplification). If retry is required AND no cookie is
		// present, issue one — wrapped in the dial-nonce envelope when
		// present so the initiator's pendingDial channel routes it back.
		if HasRetryPrefix(innerMsg) {
			validated, ok := l.transport.retryGuard.ValidateAndStrip(innerMsg, addr, time.Now())
			if !ok {
				l.drops.count(DropRetryCookieInvalid)
				// Observability: this drop is otherwise SILENT and it strands
				// the initiator until its msg2 deadline — the cookie is bound
				// to this process's retryGuard secret and the source IP, so a
				// responder restart or a source-IP change turns every dial from
				// that peer into a timeout with no signal anywhere.
				dbgHandshake.Printf("RETRY cookie REJECTED from %s (inner=%dB) — dropping msg1; initiator stalls to msg2 timeout", addr, len(innerMsg))
				l.mu.Unlock()
				return
			}
			innerMsg = validated
		} else if l.transport.requireRetryToken && !isTrustedNoAmplifySource(addr) {
			token := l.transport.retryGuard.IssueToken(addr, time.Now())
			l.drops.count(DropRetryTokenIssued)
			dbgHandshake.Printf("RETRY token issued to %s (dialNonceWrapped=%t)", addr, dialNonce != nil)
			out := token
			if dialNonce != nil {
				out = make([]byte, 0, 1+dialNonceLen+len(token))
				out = append(out, dialNoncePrefix)
				out = append(out, dialNonce...)
				out = append(out, token...)
			}
			l.mu.Unlock()
			_, _ = l.writeRelayAware(addr, out)
			return
		}

		prologue, scopeID, patFlag, noiseMsg, ok := l.resolveHandshakeKey(innerMsg)
		if !ok {
			l.drops.count(DropHandshakeKeyUnresolved)
			l.mu.Unlock()
			return
		}

		// Select handshake pattern based on initiator's flag
		hsPattern := noise.HandshakeXX
		if patFlag == patternFlagXK {
			hsPattern = noise.HandshakeXK
			dbgHandshake.Printf("Responder using XK pattern (initiator has our static key)")
		}

		state, err := noise.NewHandshakeState(noise.Config{
			Pattern:     hsPattern,
			Initiator:   false,
			Prologue:    prologue,
			CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			StaticKeypair: noise.DHKey{
				Private: append([]byte(nil), l.transport.staticPriv...),
				Public:  append([]byte(nil), l.transport.staticPub...),
			},
			Random: rand.Reader,
		})
		if err != nil {
			l.mu.Unlock()
			return
		}
		hs = &listenerHandshake{state: state, created: time.Now(), scopeID: scopeID, dialNonce: dialNonce}
		l.evictOldestHandshakeLocked() // AE-P-21: hard cap on incomplete-handshake map
		l.handshakes[key] = hs

		// Process the first message (stripped of preamble + fingerprint)
		if _, _, _, err := state.ReadMessage(nil, noiseMsg); err != nil {
			delete(l.handshakes, key)
			l.mu.Unlock()
			return
		}
		payload, err := l.transport.encodeNodeInfo()
		if err != nil {
			delete(l.handshakes, key)
			l.mu.Unlock()
			return
		}
		response, _, _, err := state.WriteMessage(nil, payload)
		if err != nil {
			delete(l.handshakes, key)
			l.mu.Unlock()
			return
		}
		// Cache the RAW msg2 and echo the dial nonce at SEND time, never
		// bake the nonce into the cache. listenerHandshake is keyed by
		// ADDRESS and lives for the 30s prune TTL, so a later msg1 from
		// this peer can legitimately belong to a DIFFERENT dial with a
		// FRESH nonce (the initiator unregisters its nonce the moment a
		// dial times out — one lost msg2 is enough). Caching the wrapped
		// bytes made the retransmit path answer that new dial with the
		// dead nonce; dispatchToPendingDial has no channel for it, drops
		// it, and the new dial times out too — re-dialing inside the same
		// window, forever. See handshake_redial_nonce_test.go.
		hs.responded = true
		hs.response = response
		l.mu.Unlock()
		_, _ = l.writeRelayAware(addr, wrapDialResponse(dialNonce, response))
		return
	}

	// Existing handshake (third message)
	state := hs.state
	scopeID := hs.scopeID

	// Strip the dial-nonce envelope if present. msg3 now carries it (as msg1
	// always has) so the classifier routes it as PacketDial instead of
	// coin-flipping it into the QUIC demux — see the wrapDialResponse call on
	// the initiator side. Tolerates a bare msg3 so a peer on an older build,
	// which still sends it raw, keeps interoperating (its msg3 simply retains
	// the ~50% misroute until it upgrades).
	msg3 := msg
	stripped := false
	if n := currentDialNonce(msg); n != nil {
		msg3 = msg[1+dialNonceLen:]
		stripped = true
	}

	// Process the third message (Initiator -> Responder)
	// This message completes the handshake and establishes the session.
	payload, cs1, cs2, err := state.ReadMessage(nil, msg3)
	if err != nil && stripped {
		// AER-020: the 0xFD-prefix strip is heuristic — a bare msg3 whose first
		// ciphertext byte is coincidentally 0xFD (1/256, notably the cross-org
		// raw-msg3 path) would be mis-stripped by 9 bytes and fail here. Retry
		// with the UNstripped bytes before treating this as a failed msg3.
		// flynn/noise checkpoints and rolls back symmetric state on a failed
		// ReadMessage, so the retry is safe.
		if p2, c1b, c2b, err2 := state.ReadMessage(nil, msg); err2 == nil {
			payload, cs1, cs2, err = p2, c1b, c2b, nil
		}
	}
	if err != nil {
		// Not a valid msg3. If we have already sent msg2, this is almost
		// certainly a retransmitted msg1 — the initiator re-sending
		// because our msg2 was lost. Re-send the cached msg2 and KEEP
		// the handshake state; the old behaviour (delete) turned a
		// single dropped msg2 into a failed handshake.
		if hs.responded && hs.response != nil {
			// Re-wrap with THIS msg1's dial nonce, not the one the cached
			// msg2 was first sent under. The initiator drops its nonce when
			// a dial times out and re-dials with a fresh one, so answering
			// with the stale nonce is unroutable at dispatchToPendingDial
			// and strands every subsequent dial from this peer.
			resp := wrapDialResponse(currentDialNonce(msg), hs.response)
			l.mu.Unlock()
			_, _ = l.writeRelayAware(addr, resp)
			return
		}
		delete(l.handshakes, key)
		l.mu.Unlock()
		return
	}
	remoteNode, remoteIdentity, remoteCaps, remoteMaxAckDelayUS, err := l.transport.verifyNodeInfo(state.PeerStatic(), payload, "")
	if err != nil {
		delete(l.handshakes, key)
		l.mu.Unlock()
		return
	}

	// Cache the peer's static key for future XK reconnections
	l.transport.cachePeerKey(remoteNode, state.PeerStatic())

	// In Noise XX/XK, after handshake:
	// - cs1 is for initiator→responder (responder uses for recv)
	// - cs2 is for responder→initiator (responder uses for send)
	nc := newNoiseConnListener(l, cs2, cs1, addr, remoteNode, remoteIdentity)
	nc.scopeID = scopeID
	nc.peerMaxAckDelay = decodeMaxAckDelay(remoteMaxAckDelayUS)

	// Negotiate explicit nonce mode if both sides support it
	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
	}
	// Simultaneous-dial deterministic tiebreak. When the peer has
	// concurrently dialed us, both directions complete a handshake at
	// nearly the same time and BOTH would Put into the session map at
	// the same key (the peer's listener port). Without coordination, the
	// second Put silently displaces the first, then any close on the
	// displaced session clobbers the surviving session's map slot —
	// orphaning a live conversation.
	//
	// Tiebreak rule (matches the upper-layer mesh dedup): keep the
	// session where the lower-NodeID peer is the initiator. As responder
	// here we keep this session only if our NodeID is HIGHER than the
	// peer's — i.e., the peer is the lower-NodeID side and SHOULD be
	// the initiator. If we are lower, our outbound dial is the
	// preferred conversation and this inbound is closed.
	//
	// Applied only when an existing session is already registered for
	// this NodeID — for first-time dials there is nothing to deduplicate.
	// On a winning replacement we close the displaced outbound; the
	// identity-matched parentStop ensures that close does not disturb
	// the new entry we are about to install.
	if existing := l.sessions.Get(remoteNode); existing != nil {
		// AER-004: only honour the deterministic tiebreak when the existing
		// session is actually ALIVE. A peer that restarted (commonly on a new
		// IP after a redeploy) leaves a dead session registered under its
		// NodeID; sacrificing the freshly-completed handshake to that corpse
		// makes the new session go dark immediately and loop (dial succeeds →
		// reaped in 30–120s → redial → loses the tiebreak again) until the
		// corpse idle-times out. If the existing session is closed, the new
		// one wins regardless of NodeID ordering.
		existingConn := connFromSession(existing)
		existingDead := existingConn == nil || existingConn.IsClosed()
		localLower := string(l.transport.localNode) < string(remoteNode)
		if !existingDead && localLower {
			// Existing (our outbound) is alive and is the preferred
			// conversation. Close this inbound loser.
			dbgHandshake.Printf("simultaneous-dial: closing inbound from %s (local %s < remote, existing alive)",
				remoteNode.Short(), l.transport.localNode.Short())
			delete(l.handshakes, key)
			l.mu.Unlock()
			nc.Close()
			return
		}
		// Either the existing session is dead, or we are the higher NodeID:
		// this inbound wins. Close the displaced/dead existing asynchronously
		// so it doesn't block our Put.
		dbgHandshake.Printf("simultaneous-dial: displacing existing for %s (dead=%v, local %s)",
			remoteNode.Short(), existingDead, l.transport.localNode.Short())
		go existing.Close()
	}
	l.sessions.Put(remoteNode, key, scopeID, &noiseConnSession{conn: nc, nodeID: remoteNode})
	delete(l.handshakes, key)

	// Issue session ticket for 0.5-RTT reconnection (if ticket store is
	// configured). The ticket captures both CipherStates while they're
	// still pristine (nonce=0) so a future resume can derive fresh
	// traffic keys identical to this handshake's output.
	//
	// Co-location shortcut: every mesh node is both initiator AND
	// responder for its peers. When node A accepts a session from B here,
	// A also populates its OWN initiatorTickets cache with the resume
	// material so that next time A dials B (out-of-band), A can present
	// the ticket. For asymmetric topologies (B never accepts from A but
	// wants to resume dialing A), B needs the material delivered over
	// the wire — see TODO below for the 0xFA delivery packet.
	if l.transport.ticketStore != nil {
		if ticket, err := l.transport.ticketStore.IssueTicket(remoteNode, cs2, cs1, remoteCaps, scopeID); err == nil {
			dbgHandshake.Printf("Issued session ticket for %s (%d bytes)", remoteNode.Short(), len(ticket))
			// Build the resume material from the responder's perspective
			// captured pre-session. Initiator needs swapped keys: their
			// send = our recv (cs1), their recv = our send (cs2).
			material := &resumeMaterial{
				Opaque:    ticket,
				SendKey:   cs1.UnsafeKey(),
				RecvKey:   cs2.UnsafeKey(),
				Caps:      remoteCaps,
				ExpiresAt: time.Now().Add(l.transport.ticketStore.ttl),
			}
			// Populate initiator-side cache for the co-located case.
			// Node that's both responder + initiator (typical mesh)
			// has the material ready for its own re-dials.
			if l.transport.initiatorTickets != nil {
				l.transport.initiatorTickets.Store(remoteNode, material)
			}
			// Cross-host delivery: send resume material to the remote
			// initiator as the first encrypted frame on the new
			// session. Wrapped in an Aether HANDSHAKE frame so the
			// initiator's adapter dispatches it via handleHandshake
			// without any custom UDP demux. Consumes cs2 nonce 0 on
			// both sides — subsequent session traffic starts at
			// nonce 1. The ticket snapshot captures pre-consumption
			// state (nonce=0 on both CipherStates), so the future
			// resume restores to nonce=0 independently; no loss.
			deliverResumeMaterial(nc, material)
		}
	}

	l.mu.Unlock()
	s := aether.NewConnection(l.transport.localNode, remoteNode, nc, aether.ProtoNoise)
	s.OnClose(func() { nc.Close() })
	// AER-019: hand the accepted session to the Accept queue from a GOROUTINE,
	// not inline on the readLoop. handleHandshake runs on the single readLoop;
	// blocking here on a full l.incoming (a slow/stalled Accept consumer) would
	// stall ALL packet dispatch on this socket — data, ACKs, and in-flight dial
	// responses — presenting as node-wide handshake/session timeouts. The
	// recover guards l.incoming being closed on shutdown (matches the relay
	// accept path); a listener not draining within the timeout drops the
	// session rather than leaking a goroutine.
	go func() {
		defer func() { _ = recover() }()
		select {
		case l.incoming <- aether.IncomingSession{Session: s, Reader: nc, Writer: nc}:
		case <-ctx.Done():
			nc.Close()
		case <-time.After(acceptHandoffTimeout):
			nc.Close()
		}
	}()
}

// resolveHandshakeKey extracts the prologue key, optional scope ID, pattern flag,
// and noise message from an incoming handshake initiation packet.
//
// Wire format: [optional preamble][CRC32 4B][pattern flag 1B][noise msg]
//
// If the transport has a TenantKeyResolver and the packet starts with a preamble,
// the scope ID is extracted and keys are resolved dynamically.
// Otherwise, the packet is assumed to start with a CRC32 fingerprint and keys
// are looked up from the transport's static keyMap.
func (l *noiseListener) resolveHandshakeKey(msg []byte) (prologue []byte, scopeID string, patternFlag byte, noiseMsg []byte, ok bool) {
	// Check for preamble (shared transport mode)
	if l.transport.tenantKeyResolver != nil && HasPreamble(msg) {
		tid, rest, err := DecodePreamble(msg)
		if err != nil {
			dbgHandshake.Printf("Failed to decode preamble: %v", err)
			return nil, "", 0, nil, false
		}
		// rest should start with CRC32 fingerprint + pattern flag + noise msg
		if len(rest) < 5 {
			return nil, "", 0, nil, false
		}
		keys, err := l.transport.tenantKeyResolver.ResolveKeys(tid)
		if err != nil {
			dbgHandshake.Printf("Unknown scope in preamble: %s: %v", tid, err)
			return nil, "", 0, nil, false
		}
		// Verify the CRC32 fingerprint matches one of the scope's keys
		fingerprint := binary.BigEndian.Uint32(rest[:4])
		for _, k := range keys {
			if transportCrypto.CRC32Hash(k) == fingerprint {
				pf := rest[4]
				dbgHandshake.Printf("Preamble resolved scope %q (fingerprint: %x, pattern: %d)", tid, fingerprint, pf)
				return k, tid, pf, rest[5:], true
			}
		}
		dbgHandshake.Printf("CRC32 mismatch for scope %q (fingerprint: %x)", tid, fingerprint)
		return nil, "", 0, nil, false
	}

	// Dedicated transport mode: no preamble, CRC32 fingerprint + pattern flag at start
	if len(msg) < 5 {
		return nil, "", 0, nil, false
	}
	fingerprint := binary.BigEndian.Uint32(msg[:4])
	prologue, found := l.transport.keyManager.LookupByFingerprint(fingerprint)
	if !found {
		return nil, "", 0, nil, false
	}
	return prologue, "", msg[4], msg[5:], true
}

// initiatorRetryInterval is how often performInitiatorHandshakeAttempt
// retransmits msg1 while waiting for msg2 on a raw UDP socket. 800ms is
// short enough to recover from a single drop within a 5s handshake
// budget (gives ~6 attempts) and long enough that a slow responder isn't
// flooded with duplicates. The responder ignores msg1 once it's already
// started building msg2 so duplicates are harmless.
const initiatorRetryInterval = 800 * time.Millisecond

// readWithMsg1Retry reads from udpConn while periodically resending the
// msg1 packet. Returns the number of bytes read on success, or an error
// if the deadline elapses before any msg2 arrives.
//
// The strategy: set a short per-read deadline (initiatorRetryInterval),
// then loop: try read → on timeout re-send msg1 + set a fresh short
// deadline → on any other error or success return. The cumulative budget
// is the supplied 'deadline' (passed by the caller); we never poll past
// it. Was H-Handshake-Retx — a single dropped msg1 OR msg2 datagram
// caused the entire 5s handshake budget to spin idle waiting for a
// reply that the responder never knew to send.
func readWithMsg1Retry(udpConn *net.UDPConn, msg1 []byte, buf []byte, deadline time.Time) (int, error) {
	for {
		now := time.Now()
		if !now.Before(deadline) {
			return 0, fmt.Errorf("handshake deadline exceeded")
		}
		nextDeadline := now.Add(initiatorRetryInterval)
		if nextDeadline.After(deadline) {
			nextDeadline = deadline
		}
		if err := udpConn.SetReadDeadline(nextDeadline); err != nil {
			return 0, err
		}
		n, err := udpConn.Read(buf)
		if err == nil {
			return n, nil
		}
		// time.Now() crossing the per-read deadline triggers net.Error
		// with Timeout()=true. Any other error (closed conn, refused,
		// etc.) is terminal.
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			return 0, err
		}
		if time.Now().Before(deadline) {
			// Resend msg1 and loop.
			if _, werr := udpConn.Write(msg1); werr != nil {
				return 0, werr
			}
			dbgHandshake.Printf("Retransmitting msg1 (no msg2 within %v)", initiatorRetryInterval)
			continue
		}
		return 0, err
	}
}
