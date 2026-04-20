//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"net"
	"sync"
	"time"
)

// PacketType identifies the protocol of a UDP packet by its first byte.
type PacketType int

const (
	PacketSTUN  PacketType = iota // 0x00-0x3F (RFC 5389)
	PacketQUIC                    // 0x40-0xBF (QUIC long/short headers)
	PacketNoise                   // 0xC0-0xFC (Noise encrypted) or CRC32 fingerprint
	PacketDial                    // 0xFD (nonce-tagged dial handshake)
)

// ClassifyPacket determines the protocol of a UDP packet.
// Preamble detection (2-byte magic 0x5450) is checked BEFORE the QUIC byte range
// because the preamble's first byte 0x54 falls within the QUIC range (0x40-0xBF).
func ClassifyPacket(data []byte) PacketType {
	if len(data) == 0 {
		return PacketNoise
	}
	// Check for preamble magic FIRST — 0x5450 ("TP") would be misidentified as QUIC
	// because 0x54 falls in the QUIC range (0x40-0xBF).
	if len(data) >= 2 && data[0] == 0x54 && data[1] == 0x50 {
		return PacketNoise // preamble-bearing Noise handshake
	}
	b := data[0]
	switch {
	case b <= 0x3F:
		return PacketSTUN
	case b >= 0x40 && b <= 0xBF:
		return PacketQUIC
	case b == dialNoncePrefix: // 0xFD
		return PacketDial
	default:
		return PacketNoise
	}
}

// DemuxPacketConn wraps a shared UDP socket and routes QUIC packets to a
// virtual PacketConn that quic-go can use. Non-QUIC packets are ignored
// (handled by the Noise listener directly).
type DemuxPacketConn struct {
	underlying *net.UDPConn
	ipv6Conn   *net.UDPConn // optional IPv6 socket for dual-stack writes
	inbox      chan packetMsg
	closed     chan struct{}
	closeOnce  sync.Once
}

type packetMsg struct {
	data []byte
	addr net.Addr
}

// NewDemuxPacketConn creates a virtual PacketConn for QUIC on a shared UDP socket.
func NewDemuxPacketConn(conn *net.UDPConn) *DemuxPacketConn {
	return &DemuxPacketConn{
		underlying: conn,
		inbox:      make(chan packetMsg, 256),
		closed:     make(chan struct{}),
	}
}

// DeliverQUICPacket routes a QUIC packet to the virtual conn's inbox.
// Called by the Noise listener when it detects a QUIC packet.
func (d *DemuxPacketConn) DeliverQUICPacket(data []byte, addr net.Addr) {
	select {
	case d.inbox <- packetMsg{data: data, addr: addr}:
	case <-d.closed:
	default: // drop if full
	}
}

// ReadFrom implements net.PacketConn — QUIC reads from the inbox.
func (d *DemuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case msg := <-d.inbox:
		n := copy(p, msg.data)
		return n, msg.addr, nil
	case <-d.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements net.PacketConn — writes go to the correct socket based on address family.
func (d *DemuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return d.underlying.WriteTo(p, addr)
	}
	// IPv6 targets use the IPv6 socket when available
	if udpAddr.IP.To4() == nil && d.ipv6Conn != nil {
		return d.ipv6Conn.WriteToUDP(p, udpAddr)
	}
	return d.underlying.WriteToUDP(p, udpAddr)
}

// Close implements net.PacketConn.
func (d *DemuxPacketConn) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil // don't close the underlying — Noise listener owns it
}

// LocalAddr implements net.PacketConn.
func (d *DemuxPacketConn) LocalAddr() net.Addr {
	return d.underlying.LocalAddr()
}

// SetDeadline implements net.PacketConn.
func (d *DemuxPacketConn) SetDeadline(t time.Time) error      { return nil }
func (d *DemuxPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *DemuxPacketConn) SetWriteDeadline(t time.Time) error { return nil }
