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
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	aether "github.com/ORBTR/aether"
	vl1 "github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/metrics"
	"github.com/ORBTR/aether/relay"
	"github.com/flynn/noise"
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
	// remoteIdentity is the peer's verified ed25519 identity public key,
	// captured from verifyNodeInfo (crypto/identity.VerifyNodeInfo's 2nd
	// return) during the handshake that established this conn. Exposed via
	// RemoteIdentity() and forwarded by aether.BaseConnection so a consumer
	// holding the dialed aether.Connection can obtain the cryptographically
	// proven identity key. Nil when the establishing path carries no signed
	// NodeInfo (e.g. the 0.5-RTT resume path, which authenticates via the
	// ticket PSK, and the minimal-NodeInfo DialOverConn path).
	remoteIdentity ed25519.PublicKey
	send           *noise.CipherState
	recv           *noise.CipherState
	sendMu         sync.Mutex
	recvMu         sync.Mutex
	// rekeying guards the send-side rekey sequence so only one goroutine
	// ratchets. AER-008: ShouldRekey stays true until ResetSend at the end of
	// the sequence and the explicit-nonce send path is lock-free, so two
	// concurrent senders could both ratchet and end two keys ahead of the
	// receiver — a silent one-way blackhole.
	rekeying atomic.Bool
	inbox          chan []byte
	closed         chan struct{}
	closeOnce      sync.Once
	buffer         []byte
	maxPacket      int
	writeFunc      func([]byte) (int, error)
	localAddr      net.Addr
	parentStop     func()
	errMu          sync.RWMutex
	err            error
	transport      *NoiseTransport // Added for Relay
	scopeID        string          // Set during handshake (from preamble or config)

	// Explicit nonce mode (if both sides support capExplicitNonce)
	explicitNonce bool
	encryptor     atomic.Pointer[nonceEncryptor] // AE-M-12: atomic swap; Load() on concurrent sends, Store() on rekey. Load()!=nil when explicitNonce=true
	window        *nonceWindow                   // non-nil when explicitNonce=true

	// Health tracking
	health *transportHealth.Monitor

	// Rekey tracking
	rekey *RekeyTracker

	// crossOrgPreambleTarget — when non-empty, the listener-side
	// writeFunc prepends a routing preamble for this NodeID on every
	// outbound write. Set by the initiator dial path when
	// Target.Metadata[MetadataKeyCrossOrgPreamble]="1" so post-handshake
	// data also hairpins through the anycast-receiving machine and
	// reaches the right same-org machine in the destination app.
	crossOrgPreambleTarget aether.NodeID

	// peerMaxAckDelay is the peer's advertised max_ack_delay (RFC 9002
	// §6.2) extracted from the handshake NodeInfo payload. Used by the
	// adapter layer to seed TLP's PTO calculation at session-open —
	// previously the adapter had only a receiver-side approximation
	// max(ACKPolicy.MaxDelay, SRTT/4) because the handshake didn't
	// carry the peer's actual value. Zero means "peer did not
	// advertise" (older build) — adapter falls back to the
	// approximation. Set once in the handshake completion path before
	// the adapter ever reads it; exposed to the adapter via the
	// PeerMaxAckDelay() method, probed by NoiseSession via the
	// optional noiseConnAckDelay interface.
	peerMaxAckDelay time.Duration

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

	// OBS-18: per-decrypt AEAD latency distribution. Records the wall-
	// clock cost of every recv-side Decrypt call (both explicit-nonce
	// window.Decrypt and CipherState recv.Decrypt paths) so a bimodal
	// distribution — uncontended µs-tier vs goroutine-queued ms-tier on
	// a CPU-saturated host — surfaces as a p99/p50 split rather than a
	// single misleading average. Drained at metrics-publication time by
	// the adapter via the noiseConnStats interface (DecryptLatencySnapshot)
	// so the adapter package never imports noise/ directly. Same lock-
	// free Record / mutex-Snapshot pattern as the adapter-side
	// writeSyscallHist / recvWindowHOLHist histograms.
	decryptLatencyHist metrics.DurationHist
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

// enableExplicitNonce switches the connection to explicit-nonce mode by
// extracting raw AEAD ciphers from the CipherStates. This allows out-of-order
// packet delivery over UDP via a sliding window nonce tracker.
// Must be called before runReader() starts.
func (c *noiseConn) enableExplicitNonce() {
	sendCipher := c.send.Cipher() // marks CipherState as invalid
	recvCipher := c.recv.Cipher()
	c.encryptor.Store(newNonceEncryptor(sendCipher))
	c.window = newNonceWindow(recvCipher, c.nonceWindowSize()) // AE-L-12: honour configured NonceWindowSize
	c.explicitNonce = true
}

// nonceWindowSize resolves the explicit-nonce replay-window size from the
// transport config (cfg.NonceWindowSize -> transport.nonceWindow). Falls back
// to the safe default of 64 when the transport is unset - c.transport is nil on
// test-constructed conns and on any path that builds a noiseConn without a
// parent transport. newNonceWindow additionally clamps the result to 1..64.
// AE-L-12: both enableExplicitNonce and rekeyRecvCipher previously passed a
// hardcoded literal 64, silently ignoring the configured NonceWindowSize knob.
func (c *noiseConn) nonceWindowSize() int {
	if c.transport != nil && c.transport.nonceWindow > 0 {
		return c.transport.nonceWindow
	}
	return 64
}

// PeerMaxAckDelay returns the peer's advertised max_ack_delay (RFC 9002
// §6.2) extracted from the Noise handshake NodeInfo payload. Zero means
// "peer did not advertise" — callers (NoiseSession at session-construct
// time) fall back to a receiver-side approximation. Set once during
// handshake completion before the adapter ever observes the noiseConn,
// so no synchronisation is required.
func (c *noiseConn) PeerMaxAckDelay() time.Duration {
	return c.peerMaxAckDelay
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

	// OBS-18: time the AEAD call itself so the latency histogram
	// captures the cost goroutines pay when the host is CPU-saturated.
	// time.Now() / time.Since are nanosecond-resolution wall-clock —
	// they include any goroutine-scheduling queue time between the
	// reader and the AEAD work, which is exactly the signal we want
	// (a bimodal p50/p99 split shows when decrypt is queued vs hot-
	// path). Recorded on both success and failure paths because a
	// failing AEAD still consumed CPU before returning.
	start := time.Now()
	if c.explicitNonce {
		plaintext, err = c.window.Decrypt(nil, nil, msg)
	} else {
		c.recvMu.Lock()
		plaintext, err = c.recv.Decrypt(nil, nil, msg)
		c.recvMu.Unlock()
	}
	c.decryptLatencyHist.Record(time.Since(start))
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
		// Double-select pattern: check closed first, then try send. This
		// avoids the race between Close() and inbox send that would
		// otherwise require defer recover() to swallow sends on a closed
		// channel.
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
			drops := atomic.AddUint64(&c.inboxDrops, 1)
			// Promote the FIRST drop of a burst to log.Printf so a wedge
			// that causes silent ACK starvation surfaces immediately;
			// then log every 1000th drop unconditionally so a sustained
			// drop storm still produces signal without log spam.
			if drops == 1 || drops%1000 == 0 {
				log.Printf("[INBOX-DROP] peer=%s dropping packet (%d bytes, total drops: %d)",
					c.remoteNode, len(payload), drops)
			}
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
		// Explicit nonce mode: the nonceEncryptor's own atomic counter makes
		// concurrent Encrypt calls safe with no mutex. AE-M-12: Load() the
		// encryptor pointer atomically so a concurrent rekeySendCipher Store()
		// can't race this read (Go-memory-model data race); the encryptor
		// itself stays lock-free, so concurrent sends are unaffected.
		ct := c.encryptor.Load().Encrypt(nil, nil, data)
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

// rekeySignalRetries is the number of times maybeInitiateRekey transmits
// the PacketTypeRekey datagram before ratcheting the send cipher. UDP can
// drop a single datagram silently — the previous fire-once design left
// the sender ratcheted while the receiver wasn't, then every subsequent
// frame failed AEAD silently until the session timed out (was the
// H-Rekey-1 / C2 finding). 3 retries match what BIND's similar
// UDP-signal designs use; on a lossless network all 3 arrive harmlessly
// (the receiver ratchets idempotently on first observation).
const rekeySignalRetries = 3

// maybeInitiateRekey checks byte and time thresholds and sends a rekey signal
// if either is exceeded. The rekey signal tells the peer to ratchet its receive
// cipher, then we ratchet our send cipher. Thread-safe via sendMu.
//
// Reliability against UDP drop: PacketTypeRekey is sent N times
// (rekeySignalRetries) back-to-back before we ratchet our send cipher.
// On the receive side the FIRST signal observed ratchets the recv cipher.
// AER-029: the duplicate copies (2 and 3) do NOT decrypt successfully after
// that — they were encrypted under the OLD key, and once the receiver has
// ratcheted to the new recv key its AEAD open of those copies fails and they
// are dropped as ordinary undecryptable datagrams. The net effect (idempotent
// rekey, extra copies discarded) is the same, but via AEAD failure, not a
// successful decrypt. NOTE: if a correlated loss burst drops all N copies the
// receiver never ratchets and that direction blackholes until idle timeout
// (AER-014) — a receiver-side trial-rekey recovery is the robust fix.
// Costs three extra datagrams every rekeyByteThreshold (~64 MiB by
// default) — negligible amortized overhead in exchange for closing
// the C2 silent-decryption-failure window.
func (c *noiseConn) maybeInitiateRekey() {
	if !c.rekey.ShouldRekey() {
		return
	}
	// AER-008: only one goroutine may run the rekey sequence. Without this,
	// two concurrent senders both pass ShouldRekey (true until ResetSend at
	// the very end), both call rekeySendCipher, and the sender ends at K2
	// while the receiver ratcheted once to K1 — every later frame then fails
	// AEAD and the session is reaped ~2 min later.
	if !c.rekeying.CompareAndSwap(false, true) {
		return
	}
	defer c.rekeying.Store(false)
	// Re-check under the guard: another goroutine may have completed the
	// rekey (including ResetSend) between our ShouldRekey and the CAS.
	if !c.rekey.ShouldRekey() {
		return
	}

	dbgSession.Printf("Initiating rekey with %s (bytes: %d/%d, elapsed: %v/%v)",
		c.remoteNode, c.rekey.BytesSent(), c.rekey.ThreshBytes(),
		c.rekey.TimeSinceRekey(), c.rekey.ThreshDur())

	// Encrypt the rekey signal ONCE under the old key, then transmit the
	// resulting ciphertext N times — encryption is the only nondeterministic
	// step (nonce advance) so we can't re-Encrypt the same nonce twice.
	data := []byte{relay.PacketTypeRekey}
	var ct []byte
	if c.explicitNonce {
		ct = c.encryptor.Load().Encrypt(nil, nil, data) // AE-M-12: atomic load pairs with rekeySendCipher's Store
	} else {
		c.sendMu.Lock()
		var err error
		ct, err = c.send.Encrypt(nil, nil, data)
		c.sendMu.Unlock()
		if err != nil {
			return
		}
	}
	for i := 0; i < rekeySignalRetries; i++ {
		_, _ = c.writeFunc(ct)
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
		// AE-M-12: atomic Store pairs with the atomic Load in sendPacket/
		// maybeInitiateRekey. sendMu still serialises Rekey()+re-extract.
		c.encryptor.Store(newNonceEncryptor(c.send.Cipher()))
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
		c.window = newNonceWindow(c.recv.Cipher(), c.nonceWindowSize()) // AE-L-12: honour configured NonceWindowSize
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

// RekeyTotal returns the lifetime count of send-side rekeys completed on
// this connection (OBS-15). Pass-through to the embedded RekeyTracker.
// Probed via the adapter's noiseConnStats interface so the aether
// adapter pkg doesn't need a direct import of noise/.
func (c *noiseConn) RekeyTotal() uint64 {
	if c.rekey == nil {
		return 0
	}
	return c.rekey.TotalRekeys()
}

// RekeyBytesSinceLast returns bytes encrypted on the send path since the
// most recent rekey (or session start if no rekey has occurred yet).
// Pair with RekeyTotal — low total with high bytes-since-last on a
// session that's been live for hours suggests the byte threshold is set
// too high; high total with low bytes-since-last on a fresh session
// suggests something is bumping the time threshold artificially.
func (c *noiseConn) RekeyBytesSinceLast() uint64 {
	if c.rekey == nil {
		return 0
	}
	return c.rekey.BytesSent()
}

// DecryptLatencySnapshot returns the p50 and p99 of the recv-side AEAD
// decrypt-call wall-clock cost in microseconds (OBS-18). Probed via the
// adapter's noiseConnStats interface so the adapter package never
// imports noise/ directly — mirrors the RekeyTotal / DecryptErrors
// pass-through pattern.
//
// A bimodal p50/p99 split is the canonical signal that the host is
// CPU-saturated and decrypt goroutines are queuing behind other work:
// p50 stays in the few-µs uncontended tier while p99 climbs into the
// ms range. Both at ms scale = sustained CPU starvation; both at µs
// scale = healthy. Zero when no samples have been recorded yet (fresh
// session or test conn that hasn't carried traffic).
func (c *noiseConn) DecryptLatencySnapshot() (p50Us, p99Us uint64) {
	p50, _, p99 := c.decryptLatencyHist.PercentileSnapshot()
	return uint64(p50), uint64(p99)
}

func (c *noiseConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *noiseConn) RemoteAddr() net.Addr { return c.remote }

// RemoteIdentity returns the peer's verified ed25519 identity public key as
// proven during the handshake (crypto/identity.VerifyNodeInfo). Returns nil
// when the establishing path carries no signed NodeInfo (0.5-RTT resume,
// minimal-NodeInfo DialOverConn). aether.BaseConnection forwards this via an
// interface assertion so consumers holding the dialed aether.Connection can
// obtain the key.
func (c *noiseConn) RemoteIdentity() ed25519.PublicKey { return c.remoteIdentity }

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
func (s *noiseConnSession) Close() error                { return s.conn.Close() }
func (s *noiseConnSession) RemoteAddr() net.Addr        { return s.conn.RemoteAddr() }
func (s *noiseConnSession) RemoteNodeID() aether.NodeID { return s.nodeID }
func (s *noiseConnSession) NetConn() net.Conn           { return s.conn.conn }
func (s *noiseConnSession) Protocol() aether.Protocol   { return aether.ProtoNoise }
func (s *noiseConnSession) OnClose(fn func())           { /* noise lifecycle managed by transport */ }

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
