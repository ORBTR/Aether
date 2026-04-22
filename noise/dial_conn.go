/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	"encoding/binary"
	"fmt"
	"io"
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

// maxHandshakeFrame caps Noise handshake messages. Real messages are
// well under 200 bytes; a 4 KB ceiling catches protocol errors and
// malicious peers without cramping future extensions.
const maxHandshakeFrame = 4 * 1024

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

	Ticket         []byte
	RemotePeerHint aether.NodeID // advisory; not a gate
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

	// ValidateTicketFn runs after signature verification to enforce
	// scope/expiry/capability semantics. Returning non-nil aborts.
	ValidateTicketFn func(body []byte) error

	// ExpectedNodeID, when non-empty, pins the responder's accept to a
	// specific initiator NodeID (used by the relay when routing to a
	// specific target agent).
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
	if err := writeTicketAndFrame(conn, cfg.Ticket, msg1); err != nil {
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

// AcceptOverConn is the responder-side counterpart of DialOverConn.
func AcceptOverConn(ctx context.Context, cfg AcceptConnConfig, conn net.Conn) (aether.Connection, error) {
	if len(cfg.StaticPriv) == 0 || len(cfg.StaticPub) == 0 {
		return nil, fmt.Errorf("noise: AcceptOverConn: StaticPriv/Pub required")
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
	ticket, msg1, err := readTicketAndFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg1: %w", err)
	}
	if len(ticket) > 0 && cfg.TrustedTicketSigner != nil {
		if len(ticket) < ed25519.SignatureSize {
			return nil, fmt.Errorf("noise: ticket truncated (%d < %d)", len(ticket), ed25519.SignatureSize)
		}
		body := ticket[:len(ticket)-ed25519.SignatureSize]
		sig := ticket[len(ticket)-ed25519.SignatureSize:]
		if !ed25519.Verify(cfg.TrustedTicketSigner, body, sig) {
			return nil, fmt.Errorf("noise: ticket signature invalid")
		}
		if cfg.ValidateTicketFn != nil {
			if err := cfg.ValidateTicketFn(body); err != nil {
				return nil, fmt.Errorf("noise: ticket rejected: %w", err)
			}
		}
	}

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
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
	remoteNode, err := decodeMinimalNodeInfoID(remotePayload)
	if err != nil {
		return nil, fmt.Errorf("noise: decode remote NodeInfo: %w", err)
	}
	if string(cfg.ExpectedNodeID) != "" && remoteNode != cfg.ExpectedNodeID {
		return nil, fmt.Errorf("noise: remote node %s does not match expected %s",
			remoteNode.Short(), cfg.ExpectedNodeID.Short())
	}

	return buildAetherConnectionOverConn(cfg.LocalNodeID, remoteNode, conn, sendCS, recvCS, maxPacket), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────

// writeTicketAndFrame writes [uint16:ticketLen][ticket][uint32:msgLen][msg]
// in one Write so message-boundary substrates (DC, UDP) see it as a
// single frame.
func writeTicketAndFrame(conn net.Conn, ticket, msg []byte) error {
	buf := make([]byte, 2+len(ticket)+4+len(msg))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ticket)))
	copy(buf[2:2+len(ticket)], ticket)
	off := 2 + len(ticket)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(msg)))
	copy(buf[off+4:], msg)
	_, err := conn.Write(buf)
	return err
}

// readTicketAndFrame reads the first-message envelope. Byte-stream safe
// (TCP, WSS) — does sequential io.ReadFull calls — and message-boundary
// safe (DC, UDP) — since the producer writes it all in one go so it
// arrives as one datagram.
func readTicketAndFrame(conn net.Conn) (ticket, msg []byte, err error) {
	var ticketLenBuf [2]byte
	if _, err := io.ReadFull(conn, ticketLenBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("read ticketLen: %w", err)
	}
	ticketLen := binary.BigEndian.Uint16(ticketLenBuf[:])
	if ticketLen > 0 {
		ticket = make([]byte, ticketLen)
		if _, err := io.ReadFull(conn, ticket); err != nil {
			return nil, nil, fmt.Errorf("read ticket: %w", err)
		}
	}
	msg, err = readFrame(conn)
	return ticket, msg, err
}

func writeFrame(conn net.Conn, msg []byte) error {
	if len(msg) > maxHandshakeFrame {
		return fmt.Errorf("noise: frame too large (%d > %d)", len(msg), maxHandshakeFrame)
	}
	buf := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(msg)))
	copy(buf[4:], msg)
	_, err := conn.Write(buf)
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxHandshakeFrame {
		return nil, fmt.Errorf("noise: frame too large (%d > %d)", n, maxHandshakeFrame)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

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

// decodeMinimalNodeInfoID extracts just the NodeID from the handshake
// payload. Static key is already bound into the Noise session via the
// pattern — no need to return it separately here.
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
func buildAetherConnectionOverConn(
	local, remote aether.NodeID,
	conn net.Conn,
	sendCS, recvCS *noise.CipherState,
	maxPacket int,
) aether.Connection {
	cfg := aether.DefaultSessionConfig()
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
	s := aether.NewConnection(local, remote, nc)
	s.OnClose(func() { nc.Close() })
	return s
}
