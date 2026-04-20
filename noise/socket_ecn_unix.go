//go:build linux || darwin || freebsd || netbsd || openbsd

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"net"

	"golang.org/x/sys/unix"
)

// enableECN turns on IP_RECVTOS (v4) and IPV6_RECVTCLASS (v6) on the
// given UDP socket via SyscallConn().Control. Either or both may fail
// depending on whether the socket is v4, v6, or dual-stack — returning
// true if at least one succeeded. Errors are intentionally suppressed:
// operator-visible logging lives at the caller.
func enableECN(conn *net.UDPConn) bool {
	sc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var v4OK, v6OK bool
	_ = sc.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1); err == nil {
			v4OK = true
		}
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1); err == nil {
			v6OK = true
		}
	})
	return v4OK || v6OK
}

// ReadFromUDP reads a packet along with the IP TOS / IPv6 traffic-class
// byte delivered via socket control message. tos == 0 means either the
// packet was Not-ECT or the kernel didn't attach cmsg data (e.g. when
// the setsockopt failed at construction).
//
// Implementation uses ReadMsgUDP + ParseSocketControlMessage so a
// single read path covers both v4 IP_TOS and v6 IPV6_TCLASS. The oob
// buffer is reused across calls (constant-memory per listener goroutine).
func (r *ecnReader) ReadFromUDP(buf []byte) (n int, addr *net.UDPAddr, tos int, err error) {
	if !r.enabled {
		n, addr, err = r.conn.ReadFromUDP(buf)
		return n, addr, 0, err
	}

	var oobn int
	n, oobn, _, addr, err = r.conn.ReadMsgUDP(buf, r.oob)
	if err != nil {
		return 0, nil, 0, err
	}
	if oobn == 0 {
		return n, addr, 0, nil
	}

	msgs, parseErr := unix.ParseSocketControlMessage(r.oob[:oobn])
	if parseErr != nil {
		return n, addr, 0, nil
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS:
			if len(m.Data) >= 1 {
				tos = int(m.Data[0])
				return n, addr, tos, nil
			}
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_TCLASS:
			// IPV6_TCLASS is typically delivered as a 4-byte int in
			// host byte order. Accept either 1-byte or 4-byte
			// payloads since historic kernels disagree.
			if len(m.Data) >= 4 {
				tos = int(m.Data[0]) | int(m.Data[1])<<8 | int(m.Data[2])<<16 | int(m.Data[3])<<24
				return n, addr, tos & 0xFF, nil
			}
			if len(m.Data) >= 1 {
				tos = int(m.Data[0])
				return n, addr, tos, nil
			}
		}
	}
	return n, addr, 0, nil
}
