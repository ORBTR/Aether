/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */

package noise

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// maxHandshakeFrame caps Noise handshake messages. Real messages are
// well under 200 bytes; a 4 KB ceiling catches protocol errors and
// malicious peers without cramping future extensions.
const maxHandshakeFrame = 4 * 1024

// WriteTicketAndFrame writes an initiator's first message,
// [uint16:ticketLen][ticket][uint32:msgLen][msg], in one Write so
// message-boundary substrates (DC, UDP) see one frame. DialOverConn sends
// msg1 through it; a forwarder that screened the ticket with
// ReadTicketAndFrame re-sends the same bytes to the accepter through it.
func WriteTicketAndFrame(w io.Writer, ticket, msg []byte) error {
	if len(ticket) > 0xFFFF {
		return fmt.Errorf("noise: ticket too large (%d > 65535)", len(ticket))
	}
	if len(msg) > maxHandshakeFrame {
		return fmt.Errorf("noise: frame too large (%d > %d)", len(msg), maxHandshakeFrame)
	}
	buf := make([]byte, 2+len(ticket)+4+len(msg))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ticket)))
	copy(buf[2:2+len(ticket)], ticket)
	off := 2 + len(ticket)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(msg)))
	copy(buf[off+4:], msg)
	_, err := w.Write(buf)
	return err
}

// ReadTicketAndFrame reads an initiator's first message: the cleartext,
// unverified ticket (nil when ticketLen is 0) and the Noise msg1 frame.
// AcceptOverConn reads msg1 through it; a forwarder reads the ticket
// through it to screen a dial without running the handshake. Sequential
// io.ReadFull calls make it byte-stream safe (TCP, WSS); it is
// message-boundary safe (DC, UDP) because WriteTicketAndFrame sends one Write.
func ReadTicketAndFrame(r io.Reader) (ticket, msg []byte, err error) {
	var ticketLenBuf [2]byte
	if _, err := io.ReadFull(r, ticketLenBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("read ticketLen: %w", err)
	}
	ticketLen := binary.BigEndian.Uint16(ticketLenBuf[:])
	if ticketLen > 0 {
		ticket = make([]byte, ticketLen)
		if _, err := io.ReadFull(r, ticket); err != nil {
			return nil, nil, fmt.Errorf("read ticket: %w", err)
		}
	}
	msg, err = readFrame(r)
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

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxHandshakeFrame {
		return nil, fmt.Errorf("noise: frame too large (%d > %d)", n, maxHandshakeFrame)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
