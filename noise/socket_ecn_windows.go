//go:build windows

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"net"

	"golang.org/x/sys/windows"
)

// Windows ECN receive-side plumbing. Winsock exposes IP_RECVECN (option
// 50 on IPPROTO_IP) and IPV6_RECVECN (option 50 on IPPROTO_IPV6) which
// deliver the ECN codepoint as a WSAMSG cmsg. Enabling them here lets
// us later parse WSA_CMSG_DATA(IP_ECN) out of the oob bytes returned by
// ReadMsgUDP.
//
// Named constants: these match the Windows SDK headers. `x/sys/windows`
// at v0.43.0+ does not expose IP_RECVECN / IPV6_RECVECN directly, so
// we declare them locally with the same numeric values the SDK uses.
const (
	winIP_RECVECN   = 50
	winIPV6_RECVECN = 50
	winIP_ECN       = 50
	winIPV6_ECN     = 50
)

// enableECN turns on IP_RECVECN / IPV6_RECVECN on the given UDP socket
// via SyscallConn().Control. Returns true if either option was accepted.
// Errors are suppressed — operator-visible logging belongs to the caller.
func enableECN(conn *net.UDPConn) bool {
	sc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var v4OK, v6OK bool
	_ = sc.Control(func(fd uintptr) {
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, winIP_RECVECN, 1); err == nil {
			v4OK = true
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, winIPV6_RECVECN, 1); err == nil {
			v6OK = true
		}
	})
	return v4OK || v6OK
}

// ReadFromUDP reads a packet along with the IP_ECN / IPV6_ECN cmsg byte.
// Windows delivers the ECN codepoint directly (0-3) rather than the
// full TOS byte — we return it as the low 2 bits of the tos slot so
// isCEMarked() works uniformly across platforms.
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

	// Windows WSAMSG cmsg parsing. The header is a WSACMSGHDR:
	//     struct WSACMSGHDR {
	//         SIZE_T cmsg_len;     // 8 bytes on 64-bit
	//         INT    cmsg_level;   // 4 bytes
	//         INT    cmsg_type;    // 4 bytes
	//     }
	// followed by the cmsg_data aligned to pointer-size.
	// For IP_ECN / IPV6_ECN the data is a single INT (4 bytes).
	data := r.oob[:oobn]
	const hdrSize = 16 // SIZE_T(8) + INT(4) + INT(4), 8-byte aligned
	for len(data) >= hdrSize {
		cmsgLen := int(uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
			uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56)
		level := int(int32(uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24))
		typ := int(int32(uint32(data[12]) | uint32(data[13])<<8 | uint32(data[14])<<16 | uint32(data[15])<<24))
		if cmsgLen < hdrSize || cmsgLen > len(data) {
			break
		}
		payloadLen := cmsgLen - hdrSize
		if payloadLen >= 4 && ((level == int(windows.IPPROTO_IP) && typ == winIP_ECN) ||
			(level == int(windows.IPPROTO_IPV6) && typ == winIPV6_ECN)) {
			// ECN codepoint lives in the low 2 bits of the int.
			ecn := int(data[hdrSize]) & 0x03
			return n, addr, ecn, nil
		}
		// Advance to next cmsg, 8-byte aligned.
		advance := (cmsgLen + 7) &^ 7
		if advance <= 0 || advance > len(data) {
			break
		}
		data = data[advance:]
	}
	return n, addr, 0, nil
}
