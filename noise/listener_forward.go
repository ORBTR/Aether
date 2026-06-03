//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"net"
)

// noiseListener integration for the cross-org anycast forwarder.
//
// The listener's runReader loop calls handleForwarderPacket on every
// inbound datagram before the normal noise classify/dispatch path.
// This file owns that integration; the codec + flow tables live in
// inner_relay.go and the type setup lives in transport.go.
//
// Three branches:
//
//  1. Routing-preamble msg1 ("AE" magic): the anycast-receiving machine
//     M_r reads the cleartext target NodeID. If target is local,
//     strip the preamble and process as a normal msg1. If target is
//     remote, wrap in OpForward and send to the target's 6PN addr;
//     record the FlowID → originator mapping so OpReply unwraps work.
//
//  2. Inner relay OpForward ("RL" magic, op=1): the target machine M_t
//     receives this from M_r over 6PN. Decode src_IP/src_port,
//     register the synth-src → (M_r addr, FlowID) mapping so the
//     noise transport's reply write wraps in OpReply, and inject the
//     payload into the noise listener as if it came from src.
//
//  3. Inner relay OpReply ("RL" magic, op=2): M_r unwraps msg2/data
//     for delivery to the originator. Look up FlowID → originator,
//     write payload to originator via M_r's listener socket. This
//     preserves Fly's 5-tuple flow tracking — the originator sees
//     replies arriving from the same (IP, port) it sent msg1 to.

// writeRelayAware writes msg to addr, wrapping in an OpReply frame when
// addr is a relayed originator in the T-table. This is the common path
// for ALL listener-side outbound writes — handshake (msg2, retry token,
// cached-msg2 resends) AND session data — so a single relay decision
// point covers both lifecycles.
//
// CRITICAL: socket selection differs between the two branches. The
// direct path writes to addr (the originator's IPv4 5-tuple from Fly's
// edge) and must use the IPv4 listener socket. The relay path writes
// to relayAddr (a same-org 6PN IPv6 ULA) and must use the IPv6 listener
// socket on dual-stack binds — using the IPv4 socket fails the write.
// connFor(target) picks the right socket for each target's address
// family.
//
// When no forwarder is configured, or addr is not a relayed originator,
// the write is a plain WriteToUDP and the function returns the bytes
// written including any wire overhead (i.e., the plain wire size). When
// the write IS wrapped, the function returns len(msg) so callers that
// count payload bytes get a consistent number regardless of relay state.
func (l *noiseListener) writeRelayAware(addr *net.UDPAddr, msg []byte) (int, error) {
	if l.transport != nil && l.transport.forwarder != nil {
		if relayAddr, flowID, ok := l.transport.forwarder.LookupRelayed(addr); ok && relayAddr != nil {
			wrapped := EncodeInnerRelayReply(flowID, msg)
			if _, err := l.connFor(relayAddr).WriteToUDP(wrapped, relayAddr); err != nil {
				return 0, err
			}
			return len(msg), nil
		}
	}
	return l.connFor(addr).WriteToUDP(msg, addr)
}

// buildNoiseConnWriteFunc returns the writeFunc for a listener-style
// noiseConn (both the initiator dial path and the responder accept
// path use newNoiseConnListener, so this one builder serves both).
//
// Two cross-org branches apply per write, in priority order:
//
//  1. T-table relay (responder/M_t side): the destination is a synth
//     originator from an OpForward ingress — wrap in OpReply and send
//     to the M_r relay addr instead of `remote`.
//
//  2. Per-conn routing preamble (initiator side): nc.crossOrgPreambleTarget
//     is non-empty — prepend an EncodeRoutingPreamble(target) frame so
//     M_r can hairpin to the right machine in the destination app.
//
// Neither branch fires on same-org / direct dials (no forwarder, no
// preamble target), so the hot path stays a plain WriteToUDP.
func buildNoiseConnWriteFunc(nc *noiseConn, l *noiseListener, remote *net.UDPAddr) func([]byte) (int, error) {
	return func(msg []byte) (int, error) {
		// Check order: T-table first, then per-conn preamble. This order
		// is correct because the two flags are role-disjoint — the
		// T-table is only ever populated on M_t's OpForward ingress
		// (responder side), while crossOrgPreambleTarget is only ever
		// set on initiator-side noiseConns. Swapping the order would
		// silently break post-handshake hairpin if a future change ever
		// allowed a conn to be both.
		nt := l.transport
		// T-table relay (M_t side reply path). Writes go to the M_r
		// 6PN address — IPv6 — so we must use connFor(relayAddr) not
		// connFor(remote) which would pick the IPv4 socket.
		if nt != nil && nt.forwarder != nil {
			if relayAddr, flowID, ok := nt.forwarder.LookupRelayed(remote); ok && relayAddr != nil {
				wrapped := EncodeInnerRelayReply(flowID, msg)
				if _, err := l.connFor(relayAddr).WriteToUDP(wrapped, relayAddr); err != nil {
					return 0, err
				}
				return len(msg), nil
			}
		}
		// Initiator cross-org: prepend routing preamble so M_r hairpins.
		if target := nc.crossOrgPreambleTarget; target != "" {
			preamble := EncodeRoutingPreamble(target)
			framed := make([]byte, 0, len(preamble)+len(msg))
			framed = append(framed, preamble...)
			framed = append(framed, msg...)
			if _, err := l.connFor(remote).WriteToUDP(framed, remote); err != nil {
				return 0, err
			}
			return len(msg), nil
		}
		return l.connFor(remote).WriteToUDP(msg, remote)
	}
}

// handleForwarderPacket is the entry point invoked from runReader.
//
// Returns:
//   - substBuf, substAddr, false: the forwarder unwrapped the packet.
//     Caller should process substBuf as if from substAddr.
//   - nil, nil, true: the forwarder fully handled the packet (forwarded
//     elsewhere, written upstream as a reply, or dropped). Caller skips.
//   - nil, nil, false: not a forwarder packet. Caller proceeds normally.
//
// conn is the listener UDP socket that delivered the packet — used to
// write OpReply unwraps + OpForward emissions back out (preserves the
// 5-tuple flow that Fly's edge tracks).
func (l *noiseListener) handleForwarderPacket(buf []byte, addr *net.UDPAddr, conn *net.UDPConn) (substBuf []byte, substAddr *net.UDPAddr, consumed bool) {
	fwd := l.transport.forwarder
	if fwd == nil || len(buf) < 2 {
		return nil, nil, false
	}

	// Routing preamble — M_r side ingress from the public anycast.
	// Counter records receipt before any drop classification: without it,
	// 12/12 cross_org_preamble_dials_failed paired with 0 forwarder_drops
	// is ambiguous (packet never arrived at M_r vs. arrived and silently
	// failed). Comparing CrossOrgMsg1Received against the dialer's
	// preamble_dials_attempted reveals which side of the wire is the
	// failing layer.
	if IsRoutingPreamble(buf) {
		fwd.recordCrossOrgMsg1Received()
		return l.onRoutingPreamble(fwd, buf, addr, conn)
	}

	// Inner relay — M_t side ingress (OpForward over 6PN) or M_r side
	// reply ingress (OpReply over 6PN).
	if IsInnerRelay(buf) {
		return l.onInnerRelay(fwd, buf, addr, conn)
	}

	return nil, nil, false
}

// onRoutingPreamble runs on the anycast-receiving machine M_r. The
// cleartext preamble carries the target NodeID; if we're not it, look
// up the right same-org machine and forward via OpForward.
//
// The `conn` parameter is the socket the preamble arrived on (typically
// the IPv4 anycast socket). The OUTBOUND write to targetAddr (M_t's 6PN
// IPv6 ULA) uses connFor(targetAddr) so dual-stack binds pick the IPv6
// socket — the inbound IPv4 socket can't write to an IPv6 destination.
func (l *noiseListener) onRoutingPreamble(fwd *IntraOrgForwarder, buf []byte, addr *net.UDPAddr, conn *net.UDPConn) ([]byte, *net.UDPAddr, bool) {
	_ = conn // socket for the OpForward write is picked from targetAddr below
	target, rest, err := DecodeRoutingPreamble(buf)
	if err != nil {
		// Malformed preamble — drop and count. The dialer will retry
		// without the preamble after a timeout; if the wire format
		// ever changes version, callers MUST emit a clear log on the
		// dialer side so the bad packet doesn't go unnoticed.
		fwd.recordDrop(dropPreambleMalformed)
		dbgNoise.Printf("forwarder M_r: malformed preamble from %s (%v)", addr, err)
		return nil, nil, true
	}

	// Strip + dispatch locally when the target is us. This is also the
	// path for receivers that don't have a forwarder lookup configured
	// — they accept preambled msg1 destined for themselves.
	if target == fwd.LocalNodeID() {
		return rest, addr, false
	}

	// Non-local target: look up the same-org machine that holds the
	// target's listener. Drop if unknown — the dialer's WS fallback
	// will still establish a session.
	targetAddr, ok := fwd.Lookup(target)
	if !ok || targetAddr == nil {
		fwd.recordDrop(dropTargetUnknown)
		dbgNoise.Printf("forwarder M_r: target %s not in directory (drop preambled msg1 from %s)", target.Short(), addr)
		return nil, nil, true
	}

	// Wrap the stripped msg1 in an OpForward frame, address it to the
	// target's 6PN, and write via connFor(targetAddr) so the IPv6 socket
	// is selected on dual-stack binds. The target machine's listener
	// accepts the frame via the OpForward branch below, registers the
	// relay, and injects the payload as if it had arrived natively
	// from `addr`.
	flowID := NewFlowID()
	fwd.RegisterForwarded(flowID, addr)
	wrapped := EncodeInnerRelayForward(flowID, addr, rest)
	_, _ = l.connFor(targetAddr).WriteToUDP(wrapped, targetAddr)
	return nil, nil, true
}

// onInnerRelay handles both OpForward (M_t side) and OpReply (M_r side).
// The op byte and direction are determined by the frame; the listener
// doesn't need an explicit M_r vs M_t mode.
//
// For OpReply, the unwrapped payload is delivered to the originator's
// IPv4 5-tuple via connFor(origin) — that picks the IPv4 socket so
// Fly's edge 5-tuple flow tracking delivers it back to the originator
// on the original flow.
func (l *noiseListener) onInnerRelay(fwd *IntraOrgForwarder, buf []byte, addr *net.UDPAddr, conn *net.UDPConn) ([]byte, *net.UDPAddr, bool) {
	_ = conn // socket for OpReply unwrap write is picked from origin below
	dec, err := DecodeInnerRelay(buf)
	if err != nil {
		fwd.recordDrop(dropInnerRelayMalformed)
		dbgNoise.Printf("forwarder: malformed inner-relay frame from %s (%v)", addr, err)
		return nil, nil, true
	}

	switch dec.Op {
	case OpForward:
		// M_t side: addr is the M_r 6PN address that forwarded to us.
		// dec.SrcAddr is the originator's public 5-tuple. Register the
		// reverse mapping so when the noise transport replies to
		// dec.SrcAddr, the write path wraps in OpReply and sends to
		// addr (M_r) instead.
		if dec.SrcAddr == nil {
			fwd.recordDrop(dropOpForwardNoSrc)
			return nil, nil, true
		}
		fwd.RegisterRelayed(dec.SrcAddr, addr, dec.FlowID)
		// Inject the payload as if it arrived natively from the
		// originator. Subsequent noise processing keys session state
		// by addr.String(), so SubstAddr must match the originator's
		// 5-tuple — the same key the noise listener would've seen had
		// msg1 arrived directly.
		return dec.Payload, dec.SrcAddr, false

	case OpReply:
		// M_r side: look up FlowID → originator addr, write payload
		// out to the originator from the IPv4 listener socket. Fly's
		// 5-tuple NAT delivers it to the originator's edge as a reply
		// on the original (originator_IP:port, M_r_IP:port) flow.
		origin := fwd.LookupForwarded(dec.FlowID)
		if origin == nil {
			fwd.recordDrop(dropOpReplyStaleFlow)
			return nil, nil, true // stale or unknown FlowID
		}
		_, _ = l.connFor(origin).WriteToUDP(dec.Payload, origin)
		return nil, nil, true

	default:
		fwd.recordDrop(dropOpUnknown)
		return nil, nil, true
	}
}
