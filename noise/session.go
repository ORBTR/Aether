//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	vl1 "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/relay"
	"github.com/pion/stun"
)

func extractNoiseConn(session aether.Connection) (*noiseConn, error) {
	if session == nil {
		return nil, errors.New("vl1: nil session")
	}
	// Try to cast to *aether.BaseConnection
	if baseSession, ok := session.(*aether.BaseConnection); ok {
		if baseSession.Conn == nil {
			return nil, errors.New("vl1: nil connection")
		}
		nc, ok := baseSession.Conn.(*noiseConn)
		if !ok {
			return nil, errors.New("vl1: unsupported session transport")
		}
		return nc, nil
	}
	return nil, errors.New("vl1: unsupported session type")
}

type noiseConn struct {
	// conn is the substrate carrying Noise-encrypted frames. UDP is the
	// primary concrete type (listener + dial paths both pass a
	// *net.UDPConn), but widening to net.Conn lets browser-transport
	// (WASM) supply an RTCDataChannel wrapper or a WebSocket wrapper
	// via noise.DialOverConn / AcceptOverConn without duplicating the
	// whole session layer. Only the three methods Read / Write / Close
	// + LocalAddr are used through this field — all generic net.Conn.
	// UDP-specific methods (WriteToUDP) live in writeFunc which the
	// listener path sets from its own concrete *net.UDPConn.
	conn       net.Conn
	remote     *net.UDPAddr
	remoteNode aether.NodeID // Added for Relay
	send       *noise.CipherState
	recv       *noise.CipherState
	sendMu     sync.Mutex
	recvMu     sync.Mutex
	inbox      chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	buffer     []byte
	maxPacket  int
	writeFunc  func([]byte) (int, error)
	localAddr  net.Addr
	parentStop func()
	errMu      sync.RWMutex
	err        error
	transport  *NoiseTransport // Added for Relay
	scopeID   string         // Set during handshake (from preamble or config)

	// Explicit nonce mode (if both sides support capExplicitNonce)
	explicitNonce bool
	encryptor     *nonceEncryptor // non-nil when explicitNonce=true
	window        *nonceWindow   // non-nil when explicitNonce=true

	// Health tracking
	health *transportHealth.Monitor

	// Rekey tracking
	rekey *RekeyTracker

	// Observability counters (Concerns #5, #6)
	decryptErrors uint64 // atomic: failed decrypt attempts
	inboxDrops    uint64 // atomic: inbox-full drops

	// ECN CE-byte counter (#15). Socket reader (ecnReader) updates this
	// when a CE-marked datagram arrives; the aether adapter drains it
	// via the `noiseConnStats` interface and folds the total into the
	// next outbound CompositeACK. Atomic read/reset pattern mirrors the
	// adapter's own `ceObservedBytes` counter so the two layers compose
	// without extra locking.
	ceBytes uint64
}

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

func newNoiseConnListener(ptr *noiseListener, send, recv *noise.CipherState, remote *net.UDPAddr, remoteNode aether.NodeID) *noiseConn {
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
		conn:       udpConn,
		remote:     remote,
		remoteNode: remoteNode,
		send:       send,
		recv:       recv,
		inbox:      make(chan []byte, inboxSize),
		closed:     make(chan struct{}),
		maxPacket:  ptr.transport.maxPacket,
		writeFunc:  func(msg []byte) (int, error) { return udpConn.WriteToUDP(msg, remote) },
		localAddr:  udpConn.LocalAddr(),
		transport:  ptr.transport,
		health:     transportHealth.NewMonitor(0.2), // EMA alpha default, overridden by aether.healthAlpha
		rekey:      NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
	}
	nc.parentStop = func() {
		ptr.removeSession(remote)
	}
	return nc
}

// enableExplicitNonce switches the connection to explicit-nonce mode by
// extracting raw AEAD ciphers from the CipherStates. This allows out-of-order
// packet delivery over UDP via a sliding window nonce tracker.
// Must be called before runReader() starts.
func (c *noiseConn) enableExplicitNonce() {
	sendCipher := c.send.Cipher() // marks CipherState as invalid
	recvCipher := c.recv.Cipher()
	c.encryptor = newNonceEncryptor(sendCipher)
	c.window = newNonceWindow(recvCipher, 64)
	c.explicitNonce = true
}

func (c *noiseConn) runReader() {
	buf := make([]byte, c.maxPacket)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			// Deadline timeouts are not fatal — the gossip layer sets
			// temporary deadlines for exchange windows. Just retry.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			c.setError(err)
			_ = c.Close()
			return
		}
		if err := c.decryptAndDeliver(buf[:n]); err != nil {
			dbgSession.Printf("decrypt failed from %s: %v", c.remote, err)
			atomic.AddUint64(&c.decryptErrors, 1)
			continue
		}
	}
}

func (c *noiseConn) decryptAndDeliver(msg []byte) error {
	var plaintext []byte
	var err error

	if c.explicitNonce {
		plaintext, err = c.window.Decrypt(nil, nil, msg)
	} else {
		c.recvMu.Lock()
		plaintext, err = c.recv.Decrypt(nil, nil, msg)
		c.recvMu.Unlock()
	}
	if err != nil {
		return err
	}

	if len(plaintext) < 1 {
		return nil
	}

	// Update last activity on any valid packet
	c.health.RecordActivity()

	msgType := plaintext[0]
	payload := plaintext[1:]

	switch msgType {
	case relay.PacketTypeData:
		// Double-select pattern: check closed first, then try send (Concern #7).
		// This avoids the race between Close() and inbox send that previously
		// required defer recover().
		select {
		case <-c.closed:
			return io.ErrClosedPipe
		default:
		}
		select {
		case <-c.closed:
			return io.ErrClosedPipe
		case c.inbox <- append([]byte(nil), payload...):
			return nil
		default:
			atomic.AddUint64(&c.inboxDrops, 1)
			dbgSession.Printf("Inbox full for %s — dropping packet (%d bytes, total drops: %d)",
				c.remoteNode, len(payload), atomic.LoadUint64(&c.inboxDrops))
			return nil
		}
	case relay.PacketTypePing:
		// Respond with pong containing the same payload (sequence number)
		return c.sendPacket(relay.PacketTypePong, payload)
	case relay.PacketTypePong:
		// Extract sequence number from pong payload and compute accurate RTT
		if len(payload) >= 4 {
			seq := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
			c.health.RecordPongRecv(seq, c.health.PingSentAt())
		} else {
			c.health.RecordPongRecv(0, time.Time{})
		}
		return nil
	case relay.PacketTypeRekey:
		// Peer has rekeyed their send cipher — ratchet our recv cipher to match
		c.rekeyRecvCipher()
		return nil
	case relay.PacketTypeRelayRequest:
		if c.transport != nil {
			return c.transport.handleRelayRequest(c, payload)
		}
	case relay.PacketTypeRelayData:
		if c.transport != nil {
			return c.transport.handleRelayData(c, payload)
		}
	}
	return nil
}

func (c *noiseConn) sendPayload(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.sendPacket(relay.PacketTypeData, payload)
}

func (c *noiseConn) sendRelayPacket(sourceNodeID aether.NodeID, payload []byte) error {
	// Include the source NodeID so the receiver knows who sent the original packet
	data := append([]byte(sourceNodeID), payload...)
	return c.sendPacket(relay.PacketTypeRelayData, data)
}

func (c *noiseConn) sendRelayRequest(targetNodeID aether.NodeID, payload []byte) (int, error) {
	// Construct payload: [TargetNodeID][Data]
	data := append([]byte(targetNodeID), payload...)
	err := c.sendPacket(relay.PacketTypeRelayRequest, data)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *noiseConn) sendPacket(packetType byte, payload []byte) error {
	// Check if rekey is needed before encrypting (only for data packets)
	if packetType == relay.PacketTypeData {
		c.maybeInitiateRekey()
	}

	// Prepend PacketType
	data := append([]byte{packetType}, payload...)

	if c.explicitNonce {
		// Explicit nonce mode: atomic counter, no mutex needed
		ct := c.encryptor.Encrypt(nil, nil, data)
		c.rekey.AddBytesSent(uint64(len(ct)))
		_, err := c.writeFunc(ct)
		if err != nil {
			c.setError(err)
		}
		return err
	}

	// Legacy sequential nonce path
	c.sendMu.Lock()
	cipher, err := c.send.Encrypt(nil, nil, data)
	c.sendMu.Unlock()
	if err != nil {
		return err
	}
	c.rekey.AddBytesSent(uint64(len(cipher)))
	_, err = c.writeFunc(cipher)
	if err != nil {
		c.setError(err)
	}
	return err
}

// maybeInitiateRekey checks byte and time thresholds and sends a rekey signal
// if either is exceeded. The rekey signal tells the peer to ratchet its receive
// cipher, then we ratchet our send cipher. Thread-safe via sendMu.
func (c *noiseConn) maybeInitiateRekey() {
	if !c.rekey.ShouldRekey() {
		return
	}

	dbgSession.Printf("Initiating rekey with %s (bytes: %d/%d, elapsed: %v/%v)",
		c.remoteNode, c.rekey.BytesSent(), c.rekey.ThreshBytes(),
		c.rekey.TimeSinceRekey(), c.rekey.ThreshDur())

	// Send rekey signal (empty payload) — this packet is encrypted with the OLD key
	data := []byte{relay.PacketTypeRekey}
	if c.explicitNonce {
		ct := c.encryptor.Encrypt(nil, nil, data)
		_, _ = c.writeFunc(ct)
	} else {
		c.sendMu.Lock()
		cipher, err := c.send.Encrypt(nil, nil, data)
		c.sendMu.Unlock()
		if err != nil {
			return
		}
		_, _ = c.writeFunc(cipher)
	}

	// Ratchet our send cipher — all subsequent sends use the new key
	c.rekeySendCipher()
}

// rekeySendCipher ratchets the send cipher state. Called after sending a rekey signal.
func (c *noiseConn) rekeySendCipher() {
	if c.explicitNonce {
		// For explicit nonce: re-derive cipher from CipherState.Rekey()
		// Note: explicit nonce encryptor uses extracted AEAD, so we rekey
		// the underlying CipherState and re-extract
		c.sendMu.Lock()
		c.send.Rekey()
		c.encryptor = newNonceEncryptor(c.send.Cipher())
		c.sendMu.Unlock()
	} else {
		c.sendMu.Lock()
		c.send.Rekey()
		c.sendMu.Unlock()
	}
	c.rekey.ResetSend()
	dbgSession.Printf("Send cipher rekeyed for %s", c.remoteNode)
}

// rekeyRecvCipher ratchets the receive cipher state. Called when a rekey signal is received.
func (c *noiseConn) rekeyRecvCipher() {
	if c.explicitNonce {
		c.recvMu.Lock()
		c.recv.Rekey()
		c.window = newNonceWindow(c.recv.Cipher(), 64)
		c.recvMu.Unlock()
	} else {
		c.recvMu.Lock()
		c.recv.Rekey()
		c.recvMu.Unlock()
	}
	c.rekey.ResetRecv()
	dbgSession.Printf("Recv cipher rekeyed for %s", c.remoteNode)
}

func (c *noiseConn) receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, c.currentError()
	case msg, ok := <-c.inbox:
		if !ok {
			return nil, c.currentError()
		}
		return msg, nil
	}
}

func (c *noiseConn) Read(p []byte) (int, error) {
	if len(c.buffer) == 0 {
		msg, err := c.receive(context.Background())
		if err != nil {
			return 0, err
		}
		c.buffer = msg
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

// ReadContext reads with context cancellation support.
func (c *noiseConn) ReadContext(ctx context.Context, p []byte) (int, error) {
	if len(c.buffer) == 0 {
		msg, err := c.receive(ctx)
		if err != nil {
			return 0, err
		}
		c.buffer = msg
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *noiseConn) Write(p []byte) (int, error) {
	if err := c.sendPayload(context.Background(), p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *noiseConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.health.MarkClosed()
		close(c.closed)
		// Do NOT close(c.inbox) — the double-select pattern in decryptAndDeliver
		// checks c.closed before sending, so inbox does not need to be closed.
		// Closing it caused panics when runReader was still sending.
		if c.parentStop != nil {
			c.parentStop()
		}
	})
	return err
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Health Check Methods
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// SendPing sends a ping packet with a sequence number and returns the sequence.
func (c *noiseConn) SendPing() (uint32, error) {
	seq := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	c.health.RecordPingSent(seq)

	payload := make([]byte, 4)
	payload[0] = byte(seq >> 24)
	payload[1] = byte(seq >> 16)
	payload[2] = byte(seq >> 8)
	payload[3] = byte(seq)

	return seq, c.sendPacket(relay.PacketTypePing, payload)
}

// LastActivity returns the time of last received packet.
func (c *noiseConn) LastActivity() time.Time {
	return c.health.LastActivity()
}

// LastPongReceived returns the time of last pong response.
func (c *noiseConn) LastPongReceived() time.Time {
	return c.health.LastPongReceived()
}

// MissedPings returns the count of consecutive missed pings.
func (c *noiseConn) MissedPings() int {
	return c.health.MissedPings()
}

// IncrementMissedPings increments the missed ping counter.
func (c *noiseConn) IncrementMissedPings() int {
	return c.health.IncrementMissedPings()
}

// RTT returns the last measured and EMA-smoothed round-trip times.
func (c *noiseConn) RTT() (last, avg time.Duration) {
	return c.health.RTT()
}

// IsAlive returns true if the session has received data within the timeout.
func (c *noiseConn) IsAlive(timeout time.Duration) bool {
	return c.health.IsAlive(timeout)
}

// IsClosed returns true if the connection is closed.
func (c *noiseConn) IsClosed() bool {
	return c.health.IsClosed()
}

// DecryptErrors returns the total number of failed decrypt attempts.
// RecordResumeMaterial decodes an inbound HANDSHAKE_RESUME_MATERIAL
// payload (delivered as the first encrypted frame on a freshly-
// established session) and caches the result in the transport's
// initiator-side ticket store. The cache is keyed by peer NodeID so a
// future Dial against that peer can short-circuit the full XK/XX
// handshake via 0.5-RTT resume.
//
// Silently drops malformed payloads — the responder may be running an
// older aether build that sends material in a format we can't parse,
// or an attacker may be trying to prime the cache with bogus keys.
// Failed decode is not a session-fatal condition.
//
// The adapter calls this via the `resumeMaterialRecorder` interface
// probe so the aether/ adapter package doesn't need to import the
// noise/ package directly.
func (c *noiseConn) RecordResumeMaterial(data []byte) {
	if c.transport == nil || c.transport.initiatorTickets == nil {
		return
	}
	m, err := decodeResumeMaterial(data)
	if err != nil {
		dbgNoise.Printf("resume: decode inbound material failed: %v", err)
		return
	}
	c.transport.initiatorTickets.Store(c.remoteNode, m)
	dbgNoise.Printf("resume: cached material for %s (%d bytes opaque)", c.remoteNode.Short(), len(m.Opaque))
}

// RecordCEBytes folds a CE-marked datagram's size into the session's
// ECN counter. Called by the listener's ecnReader when the IP TOS byte
// carries the ECN "Congestion Experienced" codepoint (RFC 3168). The
// adapter drains this via DrainCEBytes on every outbound ACK.
func (c *noiseConn) RecordCEBytes(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&c.ceBytes, uint64(n))
}

// DrainCEBytes atomically reads and zeroes the ECN CE-byte counter.
// Exposed via the noiseConnStats interface for the aether adapter's
// sendCompositeACK path — one drain per ACK means the CEBytes field
// reports exactly what's accumulated since the previous ACK.
func (c *noiseConn) DrainCEBytes() uint64 {
	return atomic.SwapUint64(&c.ceBytes, 0)
}

func (c *noiseConn) DecryptErrors() uint64 {
	return atomic.LoadUint64(&c.decryptErrors)
}

// InboxDrops returns the total number of packets dropped due to inbox overflow.
func (c *noiseConn) InboxDrops() uint64 {
	return atomic.LoadUint64(&c.inboxDrops)
}

func (c *noiseConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *noiseConn) RemoteAddr() net.Addr { return c.remote }

// ScopeID returns the scope associated with this connection.
// Set during handshake from preamble (shared transport) or transport config (dedicated).
func (c *noiseConn) ScopeID() string { return c.scopeID }

// SetDeadline is a no-op for listener-created sessions (shared UDP socket).
// Forwarding deadlines to the shared socket would affect ALL sessions — causing
// "i/o timeout" on handshake writes from other goroutines when the deadline expires.
// Gossip exchange timeouts are handled by the context deadline, not socket deadlines.
// For dedicated sessions (direct dial), udp is a per-connection socket and deadlines
// are safe — but we still no-op for simplicity since context handles it.
func (c *noiseConn) SetDeadline(_ time.Time) error      { return nil }
func (c *noiseConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *noiseConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *noiseConn) setError(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

func (c *noiseConn) currentError() error {
	c.errMu.RLock()
	defer c.errMu.RUnlock()
	if c.err != nil {
		return c.err
	}
	return io.EOF
}

// noiseConnSession wraps *noiseConn to satisfy aether.Connection for ConnectionMap storage.
// Use connFromSession to extract the underlying *noiseConn.
type noiseConnSession struct {
	conn   *noiseConn
	nodeID aether.NodeID
}

func (s *noiseConnSession) Send(ctx context.Context, payload []byte) error {
	return s.conn.sendPayload(ctx, payload)
}
func (s *noiseConnSession) Receive(ctx context.Context) ([]byte, error) {
	return s.conn.receive(ctx)
}
func (s *noiseConnSession) Close() error                  { return s.conn.Close() }
func (s *noiseConnSession) RemoteAddr() net.Addr           { return s.conn.RemoteAddr() }
func (s *noiseConnSession) RemoteNodeID() aether.NodeID    { return s.nodeID }
func (s *noiseConnSession) NetConn() net.Conn              { return s.conn.conn }
func (s *noiseConnSession) Protocol() aether.Protocol      { return aether.ProtoNoise }
func (s *noiseConnSession) OnClose(fn func())              { /* noise lifecycle managed by transport */ }

// IsAlive implements aether.HealthReporter so ConnectionMap.Prune can evict idle sessions.
func (s *noiseConnSession) IsAlive(timeout time.Duration) bool {
	return s.conn.IsAlive(timeout)
}

// connFromSession extracts the *noiseConn from a aether.Connection stored in ConnectionMap.
// Returns nil if the session is nil or not a *noiseConnSession.
func connFromSession(sess aether.Connection) *noiseConn {
	if ncs, ok := sess.(*noiseConnSession); ok {
		return ncs.conn
	}
	return nil
}

type noiseListener struct {
	transport    *NoiseTransport
	conn         *net.UDPConn            // primary UDP socket (IPv4 on Fly, dual-stack elsewhere)
	ipv6Conn     *net.UDPConn            // optional IPv6 socket for same-origin private traffic
	mu           sync.Mutex
	handshakes   map[string]*listenerHandshake
	sessions     *aether.ConnectionMap   // addr/NodeID/scope → noiseConnSession
	incoming     chan aether.IncomingSession
	pendingDials map[string]chan []byte   // nonce hex → channel for outgoing handshake responses
	quicDemux    *DemuxPacketConn        // routes QUIC packets to quic-go
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

		// Resume (0.5-RTT): 0xFD prefix means the initiator is presenting
		// an encrypted ticket + AEAD proof tag. Handle before classify so
		// we never mistakenly route it to QUIC/STUN. Full path:
		// handleResumePacket decrypts the ticket, verifies the tag,
		// instantiates a noiseConn from the ticket's CipherState, and
		// replies with resumeAcceptPrefix + a tag proving our own key
		// possession.
		if n > 0 && buf[0] == resumePrefix {
			l.handleResumePacket(ctx, conn, append([]byte(nil), buf[:n]...), addr)
			continue
		}

		// Demux: route packets by protocol type
		pktType := ClassifyPacket(buf[:n])

		// QUIC packets → route to quic-go via demux
		if pktType == PacketQUIC && l.quicDemux != nil {
			l.quicDemux.DeliverQUICPacket(append([]byte(nil), buf[:n]...), addr)
			continue
		}

		// STUN packets
		if pktType == PacketSTUN && stun.IsMessage(buf[:n]) {
			l.transport.handleSTUNPacket(buf[:n])
			continue
		}

		// Per-source rate limit FIRST (S6) — drop silently before
		// touching the global budget so an attacker IP can't starve
		// legitimate peers. Drop without response = no amplification.
		if l.transport.sourceLimit != nil && !l.transport.sourceLimit.Allow(addr) {
			continue
		}
		// Global rate limiting check
		if !l.transport.rateLimiter.Allow(1) {
			continue
		}

		// ECN: if the kernel delivered a CE-marked datagram, fold the
		// byte count into the session's CE counter so it rides the next
		// outbound CompositeACK (CACKHasECN flag + CEBytes field). The
		// lookup mirrors dispatchToSession's key scheme so both paths
		// share the same ConnectionMap indexing.
		if isCEMarked(tos) {
			if nc := connFromSession(l.sessions.GetByAddr(addr.String())); nc != nil {
				nc.RecordCEBytes(n)
			}
		}

		msg := append([]byte(nil), buf[:n]...)
		key := addr.String()
		if l.dispatchToSession(key, msg) {
			continue
		}
		// Check if this is a response to an outgoing dial handshake
		if l.dispatchToPendingDial(msg) {
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
	_ = nc.decryptAndDeliver(msg)
	return true
}

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
