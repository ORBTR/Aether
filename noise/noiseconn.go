/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * noiseConn is the per-connection Noise session. It was split out of
 * session.go (which retains the UDP noiseListener) so that it can build for
 * GOOS=js: noiseConn runs over ANY net.Conn, so the UDP listener path and the
 * browser DialOverConn / AcceptOverConn (WASM WebSocket / DataChannel) path
 * share this one type. It reaches the owning server transport only through the
 * connHost interface, carrying no reference to the //go:build !js
 * NoiseTransport, its UDP listener, pion/stun, or the relay service. The
 * browser constructs it with a nil connHost (buildAetherConnectionOverConn in
 * dial_conn.go); every connHost call site is nil-guarded.
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	aether "github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/metrics"
	"github.com/ORBTR/aether/relay"
	"github.com/flynn/noise"
)

// connHost is the narrow surface noiseConn needs from the owning server
// transport (*NoiseTransport). Decoupling through an interface keeps noiseConn
// build-tag agnostic: the concrete NoiseTransport — and everything it drags in
// (the UDP listener, pion/stun, the relay service) — stays //go:build !js,
// while noiseConn compiles for GOOS=js. The browser DialOverConn path leaves
// this nil (all call sites nil-guard); the UDP path supplies the real
// *NoiseTransport, which satisfies this interface (assertion in transport.go).
type connHost interface {
	// hostNonceWindow is the configured explicit-nonce replay window size
	// (NoiseTransport.nonceWindow); 0 selects the default.
	hostNonceWindow() int
	// handleRelayRequest / handleRelayData dispatch inbound relay control
	// frames to the transport's relay service.
	handleRelayRequest(c *noiseConn, payload []byte) error
	handleRelayData(c *noiseConn, payload []byte) error
	// recordInitiatorResume decodes + caches initiator-side resume material
	// (formerly noiseConn.RecordResumeMaterial's body; moved behind the
	// interface so the decode/cache types stay !js).
	recordInitiatorResume(remoteNode aether.NodeID, data []byte)
}

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
	transport      connHost        // server transport (nil in the browser DialOverConn path); see connHost
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
	if c.transport != nil && c.transport.hostNonceWindow() > 0 {
		return c.transport.hostNonceWindow()
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

// rekeySignalSpacing is the schedule of DELAYS between successive rekey-signal
// copies, AFTER the first (immediate) copy. AER-014: the previous design fired
// all copies back-to-back in the same instant, so a single correlated UDP loss
// burst (the ~200ms blackouts documented for this path) took every copy at
// once — the receiver then never ratcheted its recv cipher, and that direction
// blackholed under the sender's new send key until the idle timeout, with only
// a confusing decryptErrors climb to show for it.
//
// De-correlating the copies across a window WIDER than a typical burst means
// no single blackout can swallow all of them: copies land at t=0 (immediate),
// +50ms, +150ms, +350ms. The copies are ciphertext already sealed under the
// OLD send key, so spacing them is independent of when the send cipher
// ratchets (which still happens promptly, below); a copy that arrives after
// the receiver has already ratcheted on an earlier copy fails AEAD and is
// dropped harmlessly (AER-029). Total extra cost: three datagrams dribbled out
// over 350ms every rekeyByteThreshold (~64 MiB) — negligible.
var rekeySignalSpacing = []time.Duration{
	50 * time.Millisecond,
	100 * time.Millisecond, // → +150ms absolute
	200 * time.Millisecond, // → +350ms absolute
}

// maybeInitiateRekey checks byte and time thresholds and sends a rekey signal
// if either is exceeded. The rekey signal tells the peer to ratchet its receive
// cipher, then we ratchet our send cipher. Thread-safe via sendMu.
//
// Reliability against UDP drop: PacketTypeRekey is sent once immediately and
// then re-sent on the rekeySignalSpacing schedule (t=0/+50/+150/+350ms) before
// and after we ratchet our send cipher. On the receive side the FIRST signal
// observed ratchets the recv cipher.
// AER-029: the duplicate copies do NOT decrypt successfully after that — they
// were encrypted under the OLD key, and once the receiver has ratcheted to the
// new recv key its AEAD open of those copies fails and they are dropped as
// ordinary undecryptable datagrams. The net effect (idempotent rekey, extra
// copies discarded) is the same, but via AEAD failure, not a successful
// decrypt.
// AER-014: spreading the copies over a >200ms window de-correlates them from
// the ~200ms loss bursts documented for this path, so a single blackout can no
// longer drop every copy and blackhole the direction until idle timeout.
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
	// Copy 1 goes out immediately, before the send-cipher ratchet, so in the
	// common (lossless) case the receiver ratchets its recv cipher before it
	// sees any new-key data frame. The remaining copies are dribbled out on a
	// widening schedule from a background goroutine to escape correlated loss
	// bursts (AER-014); they carry the same old-key ciphertext.
	_, _ = c.writeFunc(ct)
	go c.spaceRekeySignals(ct)

	// Ratchet our send cipher — all subsequent sends use the new key
	c.rekeySendCipher()
}

// spaceRekeySignals retransmits the pre-encrypted rekey-signal ciphertext on
// the rekeySignalSpacing schedule, exiting early if the connection closes or a
// write fails. AER-014: this is the loss-de-correlation half of the rekey
// signal — see rekeySignalSpacing. The ciphertext was sealed under the old
// send key at rekey time; the receiver ratchets on the first copy it sees and
// silently drops the rest via AEAD failure (AER-029).
func (c *noiseConn) spaceRekeySignals(ct []byte) {
	for _, d := range rekeySignalSpacing {
		select {
		case <-c.closed:
			return
		case <-time.After(d):
		}
		if _, err := c.writeFunc(ct); err != nil {
			return
		}
	}
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
	if c.transport == nil {
		return
	}
	c.transport.recordInitiatorResume(c.remoteNode, data)
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

