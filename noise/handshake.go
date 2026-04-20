//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
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
	n, err := udpConn.Read(buf)
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
	remoteNode, _, remoteCaps, err := t.verifyNodeInfo(hs.PeerStatic(), payload, path.NodeID)
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
	s := aether.NewConnection(t.localNode, remoteNode, nc)
	s.OnClose(func() { nc.Close() })
	return s, nil
}

// performInitiatorHandshakeShared performs a Noise handshake using the listener's
// shared UDP socket. Handshake responses are received via the listener's
// pendingDials channel dispatch. After completion, the session is registered
// in the listener's session map for ongoing packet dispatch.
func (t *NoiseTransport) performInitiatorHandshakeShared(ctx context.Context, listener *noiseListener, addr *net.UDPAddr, path aether.Path) (aether.Connection, error) {
	return t.performInitiatorHandshakeSharedAttempt(ctx, listener, addr, path, false)
}

// performInitiatorHandshakeSharedAttempt runs one shared-socket handshake
// attempt. `xxOnly` forces XX even if a peer key is cached — used by the
// XK-failure retry to bound recursion depth to 1 (preventing a stale-key
// loop if another goroutine re-caches the peer key during eviction).
func (t *NoiseTransport) performInitiatorHandshakeSharedAttempt(ctx context.Context, listener *noiseListener, addr *net.UDPAddr, path aether.Path, xxOnly bool) (aether.Connection, error) {
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

	// Send msg1 via correct socket (IPv4 or IPv6 based on target)
	if _, err = listener.connFor(addr).WriteToUDP(noncePacket, addr); err != nil {
		return nil, fmt.Errorf("handshake msg1: %w", err)
	}

	// Receive msg2 via pending dial channel. The responder may instead
	// reply with a RETRY packet (S3 — _SECURITY.md §3.1) to validate our
	// source address. Detect that, then re-send msg1 with the cookie
	// prepended. We accept at most one retry round-trip per handshake.
	deadline := t.handshakeDeadline(ctx)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var msg2 []byte
	retried := false
recvLoop:
	for {
		select {
		case resp := <-responseCh:
			if !retried && HasRetryPrefix(resp) {
				// Validate basic shape (length only — server proves
				// authenticity via HMAC binding when we echo it back).
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
				if _, err = listener.connFor(addr).WriteToUDP(wrapped, addr); err != nil {
					return nil, fmt.Errorf("handshake msg1 retry: %w", err)
				}
				retried = true
				continue
			}
			msg2 = resp
			break recvLoop
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
			return t.performInitiatorHandshakeSharedAttempt(ctx, listener, addr, path, true /* xxOnly */)
		}
		return nil, fmt.Errorf("%w: msg2 read: %v", aether.ErrHandshakeFailed, err)
	}
	remoteNode, _, remoteCaps, err := t.verifyNodeInfo(hs.PeerStatic(), payload, path.NodeID)
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
	if _, err = listener.connFor(addr).WriteToUDP(msg3, addr); err != nil {
		return nil, fmt.Errorf("handshake msg3: %w", err)
	}

	dbgHandshake.Printf("Shared-socket handshake complete with %s (pattern: %s)", remoteNode.Short(), pattern.Name)

	// Create session using the listener's shared socket (like listener-accepted sessions)
	nc := newNoiseConnListener(listener, sendCS, recvCS, addr, remoteNode)
	nc.scopeID = preambleTenantID

	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
	}

	// Register in listener's session map so subsequent packets are dispatched correctly
	listener.registerDialSession(addr, nc, remoteNode)

	// No separate runReader — the listener's run() loop handles all incoming packets
	s := aether.NewConnection(t.localNode, remoteNode, nc)
	s.OnClose(func() { nc.Close() })
	return s, nil
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

func (t *NoiseTransport) encodeNodeInfo() ([]byte, error) {
	caps := capExplicitNonce
	if t.ticketStore != nil {
		caps |= capSessionTicket
	}
	return t.identity.EncodeNodeInfo(caps)
}

func (t *NoiseTransport) verifyNodeInfo(peerStatic []byte, payload []byte, expected aether.NodeID) (aether.NodeID, ed25519.PublicKey, uint32, error) {
	return transportCrypto.VerifyNodeInfo(peerStatic, payload, expected)
}

type listenerHandshake struct {
	state     *noise.HandshakeState
	created   time.Time
	responded bool
	scopeID  string // Extracted from preamble (empty for dedicated transports)
	dialNonce []byte // If non-nil, echo this nonce prefix in msg2/msg3 responses
}

func (l *noiseListener) handleHandshake(ctx context.Context, key string, addr *net.UDPAddr, msg []byte) {
	l.mu.Lock()
	hs := l.handshakes[key]

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
				l.mu.Unlock()
				return
			}
			innerMsg = validated
		} else if l.transport.requireRetryToken {
			token := l.transport.retryGuard.IssueToken(addr, time.Now())
			out := token
			if dialNonce != nil {
				out = make([]byte, 0, 1+dialNonceLen+len(token))
				out = append(out, dialNoncePrefix)
				out = append(out, dialNonce...)
				out = append(out, token...)
			}
			l.mu.Unlock()
			_, _ = l.connFor(addr).WriteToUDP(out, addr)
			return
		}

		prologue, scopeID, patFlag, noiseMsg, ok := l.resolveHandshakeKey(innerMsg)
		if !ok {
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
		// Echo dial nonce prefix so initiator can route the response
		if dialNonce != nil {
			nonceResp := make([]byte, 0, 1+dialNonceLen+len(response))
			nonceResp = append(nonceResp, dialNoncePrefix)
			nonceResp = append(nonceResp, dialNonce...)
			nonceResp = append(nonceResp, response...)
			_, _ = l.connFor(addr).WriteToUDP(nonceResp, addr)
		} else {
			_, _ = l.connFor(addr).WriteToUDP(response, addr)
		}
		hs.responded = true
		l.mu.Unlock()
		return
	}

	// Existing handshake (third message)
	state := hs.state
	scopeID := hs.scopeID

	// Process the third message (Initiator -> Responder)
	// This message completes the handshake and establishes the session.
	payload, cs1, cs2, err := state.ReadMessage(nil, msg)
	if err != nil {
		delete(l.handshakes, key)
		l.mu.Unlock()
		return
	}
	remoteNode, _, remoteCaps, err := l.transport.verifyNodeInfo(state.PeerStatic(), payload, "")
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
	nc := newNoiseConnListener(l, cs2, cs1, addr, remoteNode)
	nc.scopeID = scopeID

	// Negotiate explicit nonce mode if both sides support it
	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
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
		if ticket, err := l.transport.ticketStore.IssueTicket(remoteNode, cs2, cs1, remoteCaps); err == nil {
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
	s := aether.NewConnection(l.transport.localNode, remoteNode, nc)
	s.OnClose(func() { nc.Close() })
	select {
	case l.incoming <- aether.IncomingSession{Session: s, Reader: nc, Writer: nc}:
	case <-ctx.Done():
		return
	}
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
