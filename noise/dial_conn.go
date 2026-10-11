/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Build-tag agnostic: these functions run the Noise XX handshake over
// any connected net.Conn (UDP, WebRTC DataChannel wrapper, WebSocket,
// TCP, net.Pipe). Browser WASM calls DialOverConn with a DataChannel-
// or WebSocket-backed net.Conn; the relay and agent call AcceptOverConn
// on the other side.

package noise

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"time"

	"github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	"github.com/flynn/noise"
)

// dialConnHandshakeTimeout is the default deadline for a single
// DialOverConn / AcceptOverConn operation. Short enough that a dead
// pipe doesn't block the browser for long; long enough to tolerate
// normal TURN/STUN latency.
const dialConnHandshakeTimeout = 10 * time.Second

// defaultMaxPacketOverConn is the max encrypted Aether frame size on
// DialOverConn substrates. Matches aether.NoiseConfig.MaxPacketSize's
// 64 KB default — big enough for full-state gossip exchanges, small
// enough to fit under WebRTC DataChannel's practical limit.
const defaultMaxPacketOverConn = 64 * 1024

// minimalNodeInfoSize is the fixed length of encodeMinimalNodeInfo
// output: it is a length-prefixed NodeID (1-byte len + up to 255 bytes)
// plus 32 bytes of static public key plus 1 reserved-capability byte.
// We cap NodeID at 255 bytes (vastly more than any real NodeID).
const minimalNodeInfoReservedByte = 0

// DialConnConfig supplies everything DialOverConn needs. StaticPriv +
// StaticPub + LocalNodeID are mandatory. Ticket is optional.
//
// When Ticket is non-empty it's carried in the first message alongside
// (not inside) the encrypted Noise handshake payload. AcceptOverConn
// validates the Ed25519 signature at the tail against
// TrustedTicketSigner before running Noise, so an attacker who doesn't
// have a valid ticket can't even consume handshake crypto cycles.
type DialConnConfig struct {
	LocalNodeID aether.NodeID
	StaticPriv  []byte
	StaticPub   []byte

	Ticket           []byte
	RemotePeerHint   aether.NodeID // advisory; not a gate
	HandshakeTimeout time.Duration
	MaxPacket        int
}

// AcceptConnConfig is the responder-side config.
type AcceptConnConfig struct {
	LocalNodeID aether.NodeID
	StaticPriv  []byte
	StaticPub   []byte

	// TrustedTicketSigner, when non-nil, enables ticket validation.
	// Tickets are parsed as [body][ed25519 sig (64 bytes)] and sig
	// is verified against this key.
	TrustedTicketSigner ed25519.PublicKey

	// TrustedTicketSignerFn resolves the trusted signer public key from the
	// (still unverified) ticket body, for accepters whose signer varies per
	// ticket — e.g. a relay serving many partitions, each with its own signer
	// key, that selects the key from the ticket's own scope. When set it
	// takes precedence over TrustedTicketSigner and, like it, makes ticket auth
	// mandatory. Inspecting the unverified body to CHOOSE the key is safe: the
	// signature check that follows is the gate, so a forged body may name any
	// signer but cannot forge a signature under that signer's real key.
	TrustedTicketSignerFn func(body []byte) (ed25519.PublicKey, error)

	// ValidateTicketFn runs after signature verification to enforce
	// scope/expiry/capability semantics. Returning non-nil aborts.
	ValidateTicketFn func(body []byte) error

	// ValidatePeerStaticFn runs after msg3 with the verified ticket body and
	// the initiator static key msg3 authenticated, so the caller can require
	// the key the ticket names (a grant's browserPub); non-nil aborts. The
	// ticket travels in clear, so without this hook a copied ticket opens
	// under any key. Setting it requires a ticket signer.
	ValidatePeerStaticFn func(body, peerStatic []byte) error

	// TicketNonces and TicketNonceFn, set together and only with a ticket
	// signer, let each verified ticket open one connection per accepter: a
	// nonce already recorded for the same signer key is refused, and a nonce
	// is recorded only once msg3 and ValidatePeerStaticFn pass. The accepter
	// passes one cache to every accept.
	TicketNonces *TicketNonceCache

	// TicketNonceFn reads the nonce and its expiry from the verified body.
	// expiresAt is the last instant ValidateTicketFn admits the ticket, skew
	// included: the cache forgets the nonce after it.
	TicketNonceFn func(body []byte) (nonce []byte, expiresAt time.Time, err error)

	// ExpectedNodeID, when non-empty, refuses a dialer whose stated node
	// id is not this one. The dialer writes that id itself (see
	// AcceptOverConn), so the check turns away a dial meant for another
	// node and stops no dialer that names this one: it authenticates
	// nothing.
	ExpectedNodeID aether.NodeID

	HandshakeTimeout time.Duration
	MaxPacket        int
}

// DialOverConn runs an initiator Noise XX handshake over conn. On
// success the returned aether.Connection owns conn — closing the
// session closes conn.
//
// Wire layout for the first message:
//
//	[uint16:ticketLen][ticketLen:ticket][uint32:noiseLen][noise msg1]
//
// Follow-up messages are [uint32:len][len:payload] framed.
func DialOverConn(ctx context.Context, cfg DialConnConfig, conn net.Conn) (aether.Connection, error) {
	if len(cfg.StaticPriv) == 0 || len(cfg.StaticPub) == 0 {
		return nil, fmt.Errorf("noise: DialOverConn: StaticPriv/Pub required")
	}
	if len(cfg.Ticket) > 0xFFFF {
		return nil, fmt.Errorf("noise: DialOverConn: ticket too large (%d > 65535)", len(cfg.Ticket))
	}

	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = dialConnHandshakeTimeout
	}
	maxPacket := cfg.MaxPacket
	if maxPacket <= 0 {
		maxPacket = defaultMaxPacketOverConn
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
		CipherSuite: suite,
		StaticKeypair: noise.DHKey{
			Private: append([]byte(nil), cfg.StaticPriv...),
			Public:  append([]byte(nil), cfg.StaticPub...),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new handshake: %w", err)
	}

	// Msg 1
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noise: write msg1: %w", err)
	}
	if err := WriteTicketAndFrame(conn, cfg.Ticket, msg1); err != nil {
		return nil, err
	}

	// Msg 2 — responder returns its NodeInfo payload.
	msg2, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg2: %w", err)
	}
	remotePayload, _, _, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("noise: process msg2: %w", err)
	}
	remoteNode, err := decodeMinimalNodeInfoID(remotePayload)
	if err != nil {
		return nil, fmt.Errorf("noise: decode remote NodeInfo: %w", err)
	}

	// Msg 3 — carry our own NodeInfo payload.
	myPayload, err := encodeMinimalNodeInfo(cfg.LocalNodeID, cfg.StaticPub)
	if err != nil {
		return nil, err
	}
	msg3, sendCS, recvCS, err := hs.WriteMessage(nil, myPayload)
	if err != nil {
		return nil, fmt.Errorf("noise: write msg3: %w", err)
	}
	if err := writeFrame(conn, msg3); err != nil {
		return nil, fmt.Errorf("noise: send msg3: %w", err)
	}

	return buildAetherConnectionOverConn(cfg.LocalNodeID, remoteNode, conn, sendCS, recvCS, maxPacket), nil
}

// AcceptOverConn is the responder-side counterpart of DialOverConn. It
// returns once msg3 is read and every check cfg configures has passed.
//
// What it verifies is the dialer's possession of its Noise static key
// and, as far as cfg configures them, the ticket's signature,
// ValidateTicketFn, ValidatePeerStaticFn against that static key, and the
// ticket's nonce. The returned Connection's RemoteNodeID is none of
// these: it is the node id the dialer wrote into its own msg3 payload,
// and nothing verifies it. A node id is derived from an Ed25519 identity
// key (aether.NewNodeID), the static key here is X25519, and the payload
// carries no signature linking the two, so a dialer holding an admitted
// ticket states any id it likes and is reported under it. RemoteIdentity
// reports nil for the same reason. A consumer takes the caller's
// identity, the partition and the capabilities from the verified ticket
// body, which ValidateTicketFn and ValidatePeerStaticFn receive, and uses
// RemoteNodeID only as text. TestAcceptOverConn_ReportsTheIDTheDialerStates
// holds this.
func AcceptOverConn(ctx context.Context, cfg AcceptConnConfig, conn net.Conn) (aether.Connection, error) {
	return acceptOverConn(ctx, cfg, conn, noise.DH25519)
}

// acceptOverConn is AcceptOverConn with the handshake's key agreement
// passed in as dh. AcceptOverConn passes noise.DH25519, which DialOverConn
// uses too. TestAcceptOverConn_ReplayedNonceRefusedBeforeHandshake passes
// one that counts its calls, which is how it sees that a refused ticket
// cost the accepter no key pair and no Diffie-Hellman.
func acceptOverConn(ctx context.Context, cfg AcceptConnConfig, conn net.Conn, dh noise.DHFunc) (aether.Connection, error) {
	if len(cfg.StaticPriv) == 0 || len(cfg.StaticPub) == 0 {
		return nil, fmt.Errorf("noise: AcceptOverConn: StaticPriv/Pub required")
	}
	ticketAuth := cfg.TrustedTicketSigner != nil || cfg.TrustedTicketSignerFn != nil
	if !ticketAuth && (cfg.ValidatePeerStaticFn != nil || cfg.TicketNonces != nil || cfg.TicketNonceFn != nil) {
		return nil, fmt.Errorf("noise: AcceptOverConn: ticket binding set without a ticket signer")
	}
	if (cfg.TicketNonces == nil) != (cfg.TicketNonceFn == nil) {
		return nil, fmt.Errorf("noise: AcceptOverConn: TicketNonces and TicketNonceFn are set together")
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = dialConnHandshakeTimeout
	}
	maxPacket := cfg.MaxPacket
	if maxPacket <= 0 {
		maxPacket = defaultMaxPacketOverConn
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// Msg 1 with ticket prefix.
	ticket, msg1, err := ReadTicketAndFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg1: %w", err)
	}
	// A configured signer makes the ticket mandatory: an absent, empty or
	// truncated ticket fails closed, which callers that pin no ExpectedNodeID
	// rely on to refuse ticketLen=0 under a self-minted key. With both signer
	// fields nil the block is skipped.
	var body []byte
	var signer ed25519.PublicKey
	var nonce []byte
	var nonceExpires time.Time
	if ticketAuth {
		if len(ticket) < ed25519.SignatureSize {
			return nil, fmt.Errorf("noise: ticket required (got %d bytes, need >= %d)",
				len(ticket), ed25519.SignatureSize)
		}
		body = ticket[:len(ticket)-ed25519.SignatureSize]
		sig := ticket[len(ticket)-ed25519.SignatureSize:]

		// Resolve the trusted signer. A per-ticket resolver takes precedence and
		// may read the (unverified) body to select the key; the ed25519.Verify
		// below is the gate, so key selection from an unverified body cannot let
		// a forged ticket through.
		signer = cfg.TrustedTicketSigner
		if cfg.TrustedTicketSignerFn != nil {
			s, err := cfg.TrustedTicketSignerFn(body)
			if err != nil {
				return nil, fmt.Errorf("noise: resolve ticket signer: %w", err)
			}
			if len(s) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("noise: resolved ticket signer invalid (len=%d, need %d)",
					len(s), ed25519.PublicKeySize)
			}
			signer = s
		}
		if !ed25519.Verify(signer, body, sig) {
			return nil, fmt.Errorf("noise: ticket signature invalid")
		}
		if cfg.ValidateTicketFn != nil {
			if err := cfg.ValidateTicketFn(body); err != nil {
				return nil, fmt.Errorf("noise: ticket rejected: %w", err)
			}
		}
		if cfg.TicketNonceFn != nil {
			nonce, nonceExpires, err = cfg.TicketNonceFn(body)
			if err != nil {
				return nil, fmt.Errorf("noise: ticket nonce: %w", err)
			}
			// A missing, expired or seen nonce is refused before any handshake
			// crypto runs; the nonce is recorded only after msg3 below.
			if err := cfg.TicketNonces.check(signer, nonce, nonceExpires); err != nil {
				return nil, err
			}
		}
	}

	suite := noise.NewCipherSuite(dh, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
		CipherSuite: suite,
		StaticKeypair: noise.DHKey{
			Private: append([]byte(nil), cfg.StaticPriv...),
			Public:  append([]byte(nil), cfg.StaticPub...),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("noise: new handshake: %w", err)
	}

	// Msg 1 into state — payload expected empty for XX at this stage.
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("noise: process msg1: %w", err)
	}

	// Msg 2 back to initiator carrying our NodeInfo.
	myPayload, err := encodeMinimalNodeInfo(cfg.LocalNodeID, cfg.StaticPub)
	if err != nil {
		return nil, err
	}
	msg2, _, _, err := hs.WriteMessage(nil, myPayload)
	if err != nil {
		return nil, fmt.Errorf("noise: write msg2: %w", err)
	}
	if err := writeFrame(conn, msg2); err != nil {
		return nil, fmt.Errorf("noise: send msg2: %w", err)
	}

	// Msg 3 — carries initiator's NodeInfo.
	msg3, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg3: %w", err)
	}
	remotePayload, recvCS, sendCS, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, fmt.Errorf("noise: process msg3: %w", err)
	}
	// remoteNode is the dialer's own statement; see AcceptOverConn.
	remoteNode, err := decodeMinimalNodeInfoID(remotePayload)
	if err != nil {
		return nil, fmt.Errorf("noise: decode remote NodeInfo: %w", err)
	}
	if string(cfg.ExpectedNodeID) != "" && remoteNode != cfg.ExpectedNodeID {
		return nil, fmt.Errorf("noise: remote node %s does not match expected %s",
			remoteNode.Short(), cfg.ExpectedNodeID.Short())
	}
	// hs.PeerStatic is the key msg3 proved possession of; the NodeInfo
	// payload's static key is self-asserted, so the ticket binds to this one.
	if cfg.ValidatePeerStaticFn != nil {
		if err := cfg.ValidatePeerStaticFn(body, hs.PeerStatic()); err != nil {
			return nil, fmt.Errorf("noise: ticket not bound to initiator key: %w", err)
		}
	}
	// The nonce is recorded last, so a ticket presented under the wrong key
	// is refused without consuming it, and of two concurrent handshakes on
	// one ticket only the first to reach here is admitted.
	if cfg.TicketNonces != nil {
		if err := cfg.TicketNonces.use(signer, nonce, nonceExpires); err != nil {
			return nil, err
		}
	}

	return buildAetherConnectionOverConn(cfg.LocalNodeID, remoteNode, conn, sendCS, recvCS, maxPacket), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────

// encodeMinimalNodeInfo produces the payload carried inside the Noise
// handshake: [1:nodeIDLen][nodeID bytes][32:staticPub][1:reserved]. The
// NodeID-as-string is variable-length (aether.NodeID is a base32 string
// like "vl1_..."); the static public key is always 32 bytes.
func encodeMinimalNodeInfo(id aether.NodeID, staticPub []byte) ([]byte, error) {
	if len(staticPub) != 32 {
		return nil, fmt.Errorf("noise: staticPub must be 32 bytes, got %d", len(staticPub))
	}
	idBytes := []byte(string(id))
	if len(idBytes) > 255 {
		return nil, fmt.Errorf("noise: NodeID too long (%d > 255)", len(idBytes))
	}
	out := make([]byte, 0, 1+len(idBytes)+32+1)
	out = append(out, byte(len(idBytes)))
	out = append(out, idBytes...)
	out = append(out, staticPub...)
	out = append(out, minimalNodeInfoReservedByte)
	return out, nil
}

// decodeMinimalNodeInfoID returns the NodeID a peer's handshake payload
// names, as the peer wrote it: it checks the payload's length and nothing
// else. The static key the payload carries is not compared with the key
// the handshake proved either; a caller that needs the proved key reads
// hs.PeerStatic, as acceptOverConn does for ValidatePeerStaticFn.
func decodeMinimalNodeInfoID(payload []byte) (aether.NodeID, error) {
	if len(payload) < 1 {
		return "", fmt.Errorf("noise: NodeInfo payload empty")
	}
	idLen := int(payload[0])
	if len(payload) < 1+idLen+32+1 {
		return "", fmt.Errorf("noise: NodeInfo payload truncated (%d < %d)", len(payload), 1+idLen+33)
	}
	return aether.NodeID(payload[1 : 1+idLen]), nil
}

// buildAetherConnectionOverConn wraps post-handshake state into a
// noiseConn + starts its reader + returns the aether.Connection. Used
// by both DialOverConn and AcceptOverConn — their only post-handshake
// difference is the sendCS/recvCS ordering which the caller supplies.
// remote is the id decodeMinimalNodeInfoID read from the peer's payload,
// and the Connection reports it as RemoteNodeID unchecked.
func buildAetherConnectionOverConn(
	local, remote aether.NodeID,
	conn net.Conn,
	sendCS, recvCS *noise.CipherState,
	maxPacket int,
) aether.Connection {
	cfg := aether.DefaultSessionConfig()
	// remoteIdentity is intentionally left nil: this path exchanges a
	// minimal NodeInfo (NodeID + Curve25519 static key) rather than the
	// signed ed25519 NodeInfo that verifyNodeInfo validates, so no verified
	// ed25519 identity key is available. RemoteIdentity() reports nil here.
	nc := &noiseConn{
		conn:       conn,
		remoteNode: remote,
		send:       sendCS,
		recv:       recvCS,
		inbox:      make(chan []byte, cfg.InboxSize),
		closed:     make(chan struct{}),
		maxPacket:  maxPacket,
		writeFunc:  func(msg []byte) (int, error) { return conn.Write(msg) },
		localAddr:  conn.LocalAddr(),
		health:     transportHealth.NewMonitor(0.2),
		rekey:      NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
	}
	nc.parentStop = func() { _ = conn.Close() }
	go nc.runReader()
	s := aether.NewConnection(local, remote, nc, aether.ProtoNoise)
	s.OnClose(func() { nc.Close() })
	return s
}
