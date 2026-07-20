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
	"io"
	"net"
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
	vl1 "github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	"github.com/flynn/noise"
	"github.com/pion/stun"
)

func newNoiseConnDial(conn *net.UDPConn, remote *net.UDPAddr, remoteNode aether.NodeID, send, recv *noise.CipherState, maxPacket int, nt *NoiseTransport) *noiseConn {
	cfg := vl1.DefaultSessionConfig()
	inboxSize := cfg.InboxSize
	if nt != nil && nt.inboxSize > 0 {
		inboxSize = nt.inboxSize
	}
	if inboxSize <= 0 {
		inboxSize = vl1.DefaultInboxSize
	}
	nc := &noiseConn{
		conn:       conn,
		remote:     remote,
		remoteNode: remoteNode,
		send:       send,
		recv:       recv,
		inbox:      make(chan []byte, inboxSize),
		closed:     make(chan struct{}),
		maxPacket:  maxPacket,
		writeFunc:  func(msg []byte) (int, error) { return conn.Write(msg) },
		localAddr:  conn.LocalAddr(),
		transport:  nt,
		health:     transportHealth.NewMonitor(0.2), // EMA alpha default, overridden by aether.healthAlpha
		rekey:      NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
	}
	nc.parentStop = func() {
		_ = conn.Close()
	}
	return nc
}

func newNoiseConnListener(ptr *noiseListener, send, recv *noise.CipherState, remote *net.UDPAddr, remoteNode aether.NodeID, remoteIdentity ed25519.PublicKey) *noiseConn {
	udpConn := ptr.connFor(remote)
	cfg := vl1.DefaultSessionConfig()
	inboxSize := cfg.InboxSize
	if ptr.transport != nil && ptr.transport.inboxSize > 0 {
		inboxSize = ptr.transport.inboxSize
	}
	if inboxSize <= 0 {
		inboxSize = vl1.DefaultInboxSize
	}
	nc := &noiseConn{
		conn:           udpConn,
		remote:         remote,
		remoteNode:     remoteNode,
		remoteIdentity: remoteIdentity,
		send:           send,
		recv:           recv,
		inbox:          make(chan []byte, inboxSize),
		closed:         make(chan struct{}),
		maxPacket:      ptr.transport.maxPacket,
		localAddr:      udpConn.LocalAddr(),
		transport:      ptr.transport,
		health:         transportHealth.NewMonitor(0.2), // EMA alpha default, overridden by aether.healthAlpha
		rekey:          NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
	}
	// writeFunc closes over nc so it can read crossOrgPreambleTarget on
	// every send — letting the dial path set it post-construction
	// without rebuilding the func. Closure also captures the listener
	// so socket selection (connFor) can pick the right address-family
	// socket per-write, including for relayed OpReply paths that target
	// an IPv6 6PN address while remote is an IPv4 5-tuple.
	nc.writeFunc = buildNoiseConnWriteFunc(nc, ptr, remote)
	// Identity-matched removal — see ConnectionMap.RemoveBy. A blind
	// RemoveByAddr here would clobber the WINNING session's map slot if
	// this conn had been displaced by a simultaneous-dial peer (same
	// addr key, different conn). Compare by *noiseConn pointer so the
	// close path only touches entries that still belong to us.
	nc.parentStop = func() {
		ptr.removeSessionForConn(nc)
	}
	return nc
}

type noiseListener struct {
	transport    *NoiseTransport
	conn         *net.UDPConn // primary UDP socket (IPv4 on Fly, dual-stack elsewhere)
	ipv6Conn     *net.UDPConn // optional IPv6 socket for same-origin private traffic
	mu           sync.Mutex
	handshakes   map[string]*listenerHandshake
	sessions     *aether.ConnectionMap // addr/NodeID/scope → noiseConnSession
	incoming     chan aether.IncomingSession
	pendingDials map[string]chan []byte // nonce hex → channel for outgoing handshake responses
	quicDemux    *DemuxPacketConn       // routes QUIC packets to quic-go
	// drops tallies every datagram this listener discards or diverts, by
	// reason. The receive path used to drop packets with a bare `continue`, so
	// a fleet-wide outage (msg3 misrouted into quic-go ~50% of the time) was
	// invisible: the packets just stopped existing and nothing counted them.
	// Read via DropSnapshot(). See drops.go.
	drops dropCounters
}

// connFor returns the correct UDP socket for the target address.
// IPv6 targets use ipv6Conn (if available), IPv4 targets use the primary conn.
func (l *noiseListener) connFor(addr *net.UDPAddr) *net.UDPConn {
	if addr.IP.To4() == nil && l.ipv6Conn != nil {
		return l.ipv6Conn
	}
	return l.conn
}

// Accept waits for the next incoming session.
func (l *noiseListener) Accept(ctx context.Context) (aether.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case inc, ok := <-l.incoming:
		if !ok {
			return nil, io.EOF
		}
		return inc.Session, nil
	}
}

// Close stops listening.
func (l *noiseListener) Close() error {
	return l.conn.Close()
}

// Addr returns the local address.
func (l *noiseListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *noiseListener) run(ctx context.Context) {
	defer close(l.incoming)
	go func() {
		<-ctx.Done()
		_ = l.conn.Close()
		if l.ipv6Conn != nil {
			_ = l.ipv6Conn.Close()
		}
	}()

	// Dual-stack: start IPv6 read loop in parallel if available.
	// Packets from IPv6 are handled identically to IPv4 — same handshake,
	// session dispatch, and QUIC demux logic. The IPv6 socket handles
	// same-origin private traffic (fdaa: on Fly).
	if l.ipv6Conn != nil {
		go l.runReader(ctx, l.ipv6Conn)
	}

	// G13/G14: Periodic cleanup of stale handshakes and pending dials.
	// Handshakes that don't complete within 30 seconds are leaked state.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.pruneStaleHandshakes(30 * time.Second)
			}
		}
	}()
	// Primary read loop (IPv4 or dual-stack)
	l.runReader(ctx, l.conn)
}

// runReader reads packets from a UDP socket and dispatches them.
// Used for both the primary socket and the optional IPv6 socket.
//
// ECN integration (#15): the read path uses ecnReader which enables
// IP_RECVTOS / IPV6_RECVTCLASS at socket open and extracts the IP TOS
// byte on every datagram. CE-marked packets (TOS bits 0-1 == 0b11) feed
// NoiseSession.RecordCEBytes so the next outbound CompositeACK carries
// the CEBytes extension and the remote sender reacts via cong.OnCE.
func (l *noiseListener) runReader(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, l.transport.maxPacket)
	reader := newECNReader(conn)
	if reader.Enabled() {
		dbgNoise.Printf("ECN cmsg delivery enabled on %s", conn.LocalAddr())
	}
	for {
		n, addr, tos, err := reader.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// Resume (0.5-RTT): resumePrefix (0xFA) means the initiator is
		// presenting an encrypted ticket + AEAD proof tag. Handle before
		// classify so we never mistakenly route it to QUIC/STUN. Note this
		// is 0xFA, NOT the 0xFD dialNoncePrefix — the two are distinct
		// wire prefixes and must not be conflated. Full path:
		// handleResumePacket decrypts the ticket, verifies the tag,
		// instantiates a noiseConn from the ticket's CipherState, and
		// replies with resumeAcceptPrefix + a tag proving our own key
		// possession.
		if n > 0 && buf[0] == resumePrefix {
			// AE-L-11: Resume is a first-contact / unknown-source event, not
			// established-session traffic - it MUST NOT skip the S6 throttles.
			// Apply the same per-source + global handshake-flood limits the
			// slow path below uses (session.go sourceLimit/rateLimiter), so
			// 0xFA spray from spoofed sources can't bypass them and burn CPU
			// on ticket GCM.Open + per-datagram copies with no rate limit.
			if l.transport.sourceLimit != nil && !l.transport.sourceLimit.Allow(addr) {
				l.drops.count(DropResumeSourceLimit)
				continue
			}
			if !l.transport.rateLimiter.Allow(1) {
				l.drops.count(DropResumeGlobalLimit)
				continue
			}
			l.handleResumePacket(ctx, conn, append([]byte(nil), buf[:n]...), addr)
			continue
		}

		// Demux: route packets by protocol type
		pktType := ClassifyPacket(buf[:n])

		// QUIC packets → route to quic-go via demux.
		//
		// ⚠ This branch is classified by FIRST BYTE ONLY and DeliverQUICPacket
		// validates nothing — anything in 0x40-0xBF (128 of 256 values) is
		// enqueued for quic-go, which discards it if it is not really QUIC.
		// Raw Noise ciphertext has a uniformly random first byte, so this
		// branch silently destroyed ~50% of msg3 until msg3 was moved inside
		// the dial-nonce envelope. Note the STUN branch below IS guarded by
		// stun.IsMessage (magic-cookie validated); this one has no equivalent.
		// The counter exists so the next occurrence is a lookup, not a
		// nine-hour investigation: quic_demux climbing while noise-UDP fails
		// is the signature.
		if pktType == PacketQUIC && l.quicDemux != nil {
			l.drops.count(DropQUICDemux)
			l.quicDemux.DeliverQUICPacket(append([]byte(nil), buf[:n]...), addr)
			continue
		}

		// STUN packets
		if pktType == PacketSTUN && stun.IsMessage(buf[:n]) {
			l.drops.count(DropSTUN)
			l.transport.handleSTUNPacket(buf[:n])
			continue
		}

		// Cross-org forwarder: routing preamble (M_r side) + inner
		// relay frames (both sides). MUST run BEFORE dispatchToSession
		// because forwarder may substitute addr to the originator's
		// 5-tuple — and dispatchToSession's key derives from addr.
		// When handleForwarderPacket returns (substBuf != nil), it
		// consumed a forwarder frame and the payload should be
		// processed as if it had arrived from substAddr. When
		// (consumed=true, substBuf=nil) the forwarder handled the
		// packet fully. When (consumed=false) fall through to normal
		// classification.
		//
		// The forwarder branch has its own per-source defense against
		// preamble-flood amplification (see handleForwarderPacket),
		// so we don't need the per-source bucket here to guard it.
		if l.transport.forwarder != nil {
			substBuf, substAddr, consumed := l.handleForwarderPacket(buf[:n], addr, conn)
			if consumed {
				continue
			}
			if substBuf != nil {
				// Replace the in-flight buffer + source with the
				// forwarder-unwrapped form. copy() with overlapping
				// ranges where substBuf aliases buf[hdr:] is safe —
				// Go's spec mandates memmove semantics so a
				// dst-at-lower-address forward overlap is well-defined.
				// Do NOT swap to `buf = substBuf`; the buffer is
				// reused next iteration and a fresh slice header
				// would lose the underlying capacity.
				copy(buf[:len(substBuf)], substBuf)
				n = len(substBuf)
				if substAddr != nil {
					addr = substAddr
				}
			}
		}

		// FAST PATH — established session dispatch BEFORE rate limits.
		//
		// The per-source rate limiter is sized as a HANDSHAKE-flood
		// defence (10 burst, 1/sec refill in ratelimit.go:68-76). It
		// MUST NOT apply to AEAD-authenticated data + ACK frames on
		// long-lived sessions: any active session emitting >1 packet/sec
		// sustained would exhaust its source bucket, subsequent ACKs
		// would be silently dropped, the sender's send-window would
		// never advance, and STALL-DETECT would fire with no recovery.
		//
		// AEAD-authenticated traffic on established sessions is trusted
		// — the cryptographic check is the gate. Skip the per-source +
		// global rate limits when the packet matches a known session;
		// only enforce them on packets that fall through to the
		// handshake / unknown-source path.
		//
		// ECN handling moves here too so CE marks aren't dropped on
		// rate-limited packets that would otherwise dispatch.
		key := addr.String()
		msg := append([]byte(nil), buf[:n]...)

		// SOLICITED-DIAL PATH — a response to a dial THIS node initiated.
		// It must be routed before BOTH the session fast-path below and the
		// handshake-flood limiters, because each of them silently eats it:
		//
		//   - dispatchToSession claims EVERY packet arriving from an addr
		//     that has a session entry: it discards decryptAndDeliver's
		//     error and returns true regardless. A session still mapped at
		//     the peer's addr therefore swallows this dial's RETRY token and
		//     msg2 (they are handshake frames, so the AEAD open always
		//     fails). The dial then times out, AddressTracker marks the udp
		//     endpoint dead, the upgrade walker's bestAddress() returns ""
		//     and skips the candidate forever — noise-UDP is locked out for
		//     that peer permanently and the mesh silently rides WebSocket.
		//   - the per-source limiter is a FIRST-CONTACT flood defence (10
		//     burst, 1/sec refill, keyed by IP only, so both directions to a
		//     peer machine share one bucket). The 700ms msg1 retransmit
		//     emits ~1.43/sec, outpacing refill, so a dial that begins while
		//     the bucket is low cannot self-recover.
		//
		// Running it first does not widen the flood surface: it is
		// self-gating, returning false unless the packet carries
		// dialNoncePrefix AND an 8-byte nonce matching a dial registered by
		// this node — unforgeable without guessing 64 random bits. Every
		// non-matching packet still falls through to the session path and
		// both limiters exactly as before.
		if l.dispatchToPendingDial(msg) {
			l.drops.count(DropPendingDial)
			continue
		}

		if l.dispatchToSession(key, msg) {
			if isCEMarked(tos) {
				if nc := connFromSession(l.sessions.GetByAddr(key)); nc != nil {
					nc.RecordCEBytes(n)
				}
			}
			continue
		}

		// SLOW PATH — packet did not match an established session.
		// Treat as handshake-candidate from unknown / first-contact
		// source and apply the rate limits intended for that path.
		//
		// AER-012: exempt packets for an IN-PROGRESS handshake (we already
		// hold listenerHandshake state for this address) from the per-source
		// flood bucket. That bucket (10 burst, 1/sec, keyed by IP) can't keep
		// up with the ~1.43/sec msg1/msg3 retransmit cadence, so a dial that
		// began while the bucket was low could never self-recover — a churn
		// amplifier. This does not widen the first-contact flood surface: the
		// initial msg1 still had to pass the limiter to create the entry, the
		// handshake map is hard-capped (AE-P-21), and the global limiter below
		// still applies to every packet.
		l.mu.Lock()
		_, handshakeInProgress := l.handshakes[key]
		l.mu.Unlock()
		if !handshakeInProgress && l.transport.sourceLimit != nil && !l.transport.sourceLimit.Allow(addr) {
			l.drops.count(DropSourceLimit)
			continue
		}
		if !l.transport.rateLimiter.Allow(1) {
			l.drops.count(DropGlobalLimit)
			continue
		}
		// Debug: log when packets fall through with pending dials registered
		l.mu.Lock()
		pendingCount := len(l.pendingDials)
		var pendingKeys []string
		if pendingCount > 0 {
			pendingKeys = make([]string, 0, pendingCount)
			for k := range l.pendingDials {
				pendingKeys = append(pendingKeys, k)
			}
		}
		l.mu.Unlock()
		if pendingCount > 0 {
			dbgNoise.Printf("Packet from %q fell through to handleHandshake (pending dials: %v, msg len: %d)", key, pendingKeys, len(msg))
		}
		l.handleHandshake(ctx, key, addr, msg)
	}
}

func (l *noiseListener) dispatchToSession(key string, msg []byte) bool {
	nc := connFromSession(l.sessions.GetByAddr(key))
	if nc == nil {
		return false
	}
	// Recover from panic if session is closing (send on closed channel)
	defer func() {
		_ = recover()
	}()
	err := nc.decryptAndDeliver(msg)
	if err != nil && len(msg) > 0 && msg[0] == dialNoncePrefix {
		// AER-003: AEAD failed AND this is a nonce-tagged handshake packet
		// (0xFD) — almost certainly a fresh msg1 from a peer that restarted
		// on the same 5-tuple. Do NOT claim it; return false so the readLoop
		// routes it to handleHandshake (rate-limited) instead of silently
		// eating every re-handshake until the dead session is reaped (which
		// otherwise locked the peer out for minutes and tripped the 30-min
		// address dead-cooldown). A genuine session data frame whose random
		// first byte happens to be 0xFD would have DECRYPTED successfully and
		// never reached here, so established traffic is unaffected.
		return false
	}
	// Established-session trust: a non-handshake AEAD failure (corruption,
	// replay, or a late frame) is swallowed as before — the cryptographic
	// check is the gate and we don't want garbage flooding the handshake path.
	return true
}

// dropCount exposes the listener's per-reason drop tally. See drops.go.
func (l *noiseListener) dropCount(r DropReason) uint64 { return l.drops[r].Load() }

// dialNoncePrefix marks a packet as part of a nonce-tagged dial handshake.
// This byte won't conflict with STUN (0x00-0x3F), preamble, or fingerprint packets.
const dialNoncePrefix byte = 0xFD
const dialNonceLen = 8

// dispatchToPendingDial checks if a packet has a dial nonce prefix and routes
// it to the matching pending dial channel. Returns true if dispatched.
func (l *noiseListener) dispatchToPendingDial(msg []byte) bool {
	if len(msg) < 1+dialNonceLen || msg[0] != dialNoncePrefix {
		return false
	}
	nonceKey := string(msg[1 : 1+dialNonceLen])
	payload := msg[1+dialNonceLen:]

	l.mu.Lock()
	ch := l.pendingDials[nonceKey]
	l.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- payload:
		return true
	default:
		return false
	}
}

// registerPendingDial creates a channel for receiving nonce-tagged handshake responses.
// Returns the nonce (8 bytes) and the response channel.
func (l *noiseListener) registerPendingDial() ([]byte, chan []byte) {
	nonce := make([]byte, dialNonceLen)
	rand.Read(nonce)
	nonceKey := string(nonce)
	ch := make(chan []byte, 4)
	l.mu.Lock()
	if l.pendingDials == nil {
		l.pendingDials = make(map[string]chan []byte)
	}
	l.pendingDials[nonceKey] = ch
	l.mu.Unlock()
	return nonce, ch
}

// unregisterPendingDial removes the pending dial channel for a nonce.
func (l *noiseListener) unregisterPendingDial(nonce []byte) {
	nonceKey := string(nonce)
	l.mu.Lock()
	delete(l.pendingDials, nonceKey)
	l.mu.Unlock()
}

// registerDialSession adds an outgoing session to the listener's dispatch map.
func (l *noiseListener) registerDialSession(addr *net.UDPAddr, nc *noiseConn, nodeID aether.NodeID) {
	key := addr.String()
	l.sessions.Put(nodeID, key, nc.scopeID, &noiseConnSession{conn: nc, nodeID: nodeID})
}

func (l *noiseListener) removeSession(addr *net.UDPAddr) {
	key := addr.String()
	l.sessions.RemoveByAddr(key)
}

// removeSessionForConn removes ONLY map entries whose stored connection
// is still this exact noiseConn. Safe for the close path even when a
// concurrent simultaneous-dial winner has overwritten our slot — the
// matchFn returns false for the winner's entries and the close becomes
// a no-op on those keys instead of clobbering the live session. See
// ConnectionMap.RemoveBy for full rationale.
func (l *noiseListener) removeSessionForConn(nc *noiseConn) {
	l.sessions.RemoveBy(func(sess aether.Connection) bool {
		return connFromSession(sess) == nc
	})
}

// maxIncompleteHandshakes is a hard ceiling on the number of in-flight
// (incomplete) handshake states the listener holds at once. AE-P-21:
// pruneStaleHandshakes bounds the map only by a 30s TTL, and the per-source +
// global rate limiters bound only the arrival rate. When an operator sets
// RequireRetryToken=false (transport.go, legacy-initiator interop) the
// stateless-retry anti-amplification early-return (handshake.go) is skipped, so
// spoofed first-contact msg1s each allocate a Noise HandshakeState. This cap
// sits far above any realistic concurrent legitimate incomplete-handshake
// working set yet well below the rate×TTL flood ceiling (~30k at the 1000/s
// default), so it never fires in normal operation and backstops memory.
const maxIncompleteHandshakes = 16384

// evictOldestHandshakeLocked enforces maxIncompleteHandshakes by discarding the
// oldest-created incomplete handshake when the map is at capacity. Caller MUST
// hold l.mu. Evicting the oldest (rather than rejecting the new arrival)
// preserves the ability to always accept a fresh handshake while bounding
// memory — the oldest entry is closest to its TTL and the most likely to be
// abandoned/stale. AE-P-21.
func (l *noiseListener) evictOldestHandshakeLocked() {
	if len(l.handshakes) < maxIncompleteHandshakes {
		return
	}
	var oldestKey string
	var oldestCreated time.Time
	for k, hs := range l.handshakes {
		if oldestKey == "" || hs.created.Before(oldestCreated) {
			oldestKey = k
			oldestCreated = hs.created
		}
	}
	if oldestKey != "" {
		dbgSession.Printf("AE-P-21: evicting oldest incomplete handshake %s (cap %d reached, age %v)", oldestKey, maxIncompleteHandshakes, time.Since(oldestCreated))
		delete(l.handshakes, oldestKey)
	}
}

// pruneStaleHandshakes removes incomplete handshakes and leaked pending dials
// older than maxAge. Fixes G13 (relay handshake leak) and G14 (pending dial leak).
func (l *noiseListener) pruneStaleHandshakes(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	l.mu.Lock()
	for key, hs := range l.handshakes {
		if hs.created.Before(cutoff) {
			dbgSession.Printf("Pruning stale handshake from %s (age: %v)", key, time.Since(hs.created))
			delete(l.handshakes, key)
		}
	}
	l.mu.Unlock()

	// B5: Prune external sessions (WebSocket/QUIC relay bridges) that are idle.
	// Prevents unbounded map growth from sessions that disconnected without cleanup.
	// Delegated to RelayService which now owns the external session map.
	if l.transport.relayService != nil {
		l.transport.relayService.PruneExternal(maxAge)
	}
}

// tenantForNode returns the scope ID for a node, or "" if unknown.
func (l *noiseListener) tenantForNode(nodeID aether.NodeID) string {
	nc := connFromSession(l.sessions.Get(nodeID))
	if nc != nil {
		return nc.scopeID
	}
	return ""
}
