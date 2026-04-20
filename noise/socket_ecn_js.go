//go:build js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// ECN stub for js/wasm. Browsers have no raw UDP socket — the non-native
// transport is WebSocket — so there is nothing to stub out at the cmsg
// layer. This file provides compatible types + helpers so the shared
// read loop compiles under the `js` build tag.
package noise

import "net"

type ecnReader struct {
	conn *net.UDPConn
}

func newECNReader(conn *net.UDPConn) *ecnReader { return &ecnReader{conn: conn} }

func (r *ecnReader) ReadFromUDP(buf []byte) (n int, addr *net.UDPAddr, tos int, err error) {
	n, addr, err = r.conn.ReadFromUDP(buf)
	return n, addr, 0, err
}

func (r *ecnReader) Enabled() bool { return false }

func isCEMarked(int) bool { return false }
