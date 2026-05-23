//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	aether "github.com/ORBTR/aether"
)

// Intra-org noise-UDP forwarder — the production side of the cross-org
// anycast hairpin documented in
// HSTLES/Library/docs/superpowers/plans/2026-05-23-cross-org-anycast-forwarder.md.
//
// Problem: Fly's public anycast IPv4 is per-app. An initiator's Noise
// msg1 lands on whichever of the app's N machines wins the 5-tuple
// hash. If that machine doesn't hold the target NodeID's keys (the
// 1-in-N case is rare; the (N-1)-in-N case is the common one), the
// handshake fails. Caller drops to WebSocket fallback.
//
// Fix: the anycast-receiving machine M_r inspects the cleartext
// routing preamble on msg1, looks up which machine M_t in the same
// org holds the target NodeID, and forwards the datagram via 6PN.
// M_t processes the handshake as if msg1 had arrived natively from
// the originator's 5-tuple, but its REPLIES go back through M_r so
// Fly's 5-tuple flow tracking delivers them to the originator
// correctly. The originator sees only "msg2 arrived from the same
// (IP, port) I sent msg1 to" — exactly what Noise expects.
//
// This file ships the inner relay wire codec, the M_r and M_t flow
// tables, and the IntraOrgForwarder type. NoiseTransport integration
// (listener branching + reply-write interception) is in transport.go
// and session.go. Library wiring (LAD-backed lookup + per-dial
// preamble emission) is in HSTLES/Library/mesh/node.

// ── wire format ──────────────────────────────────────────────────────
//
// op=1 forward (M_r → M_t, intra-org over 6PN):
//
//	[2 bytes: magic 0x52 0x4C ("RL")]
//	[1 byte : version (0x01)]
//	[1 byte : op (0x01)]
//	[16 bytes: flow_id]
//	[16 bytes: src_IP (IPv6 form; IPv4 = ::ffff:a.b.c.d)]
//	[2 bytes : src_port (big-endian)]
//	[N bytes : payload — the routing-preamble-stripped msg1 or data]
//
// op=2 reply (M_t → M_r, intra-org over 6PN):
//
//	[2 bytes: magic 0x52 0x4C ("RL")]
//	[1 byte : version (0x01)]
//	[1 byte : op (0x02)]
//	[16 bytes: flow_id]
//	[N bytes : payload — msg2 or data]
//
// Magic 0x524C ("RL") distinguishes the inner protocol from the
// tenant-scope preamble ("TP" 0x5450) and the routing preamble
// ("AE" 0x4145) and from raw noise msg1 (statistically uniform first
// byte from a Curve25519 ephemeral pub key).

const (
	// InnerRelayMagic identifies a packet wrapped in the M_r ↔ M_t
	// relay protocol ("RL" = ReLay).
	InnerRelayMagic uint16 = 0x524C

	// InnerRelayVersion is the current wire-format version.
	InnerRelayVersion uint8 = 0x01

	// OpForward (op=1): M_r → M_t carrying an inbound public datagram
	// with the originator's 5-tuple attached so M_t can address replies.
	OpForward uint8 = 0x01

	// OpReply (op=2): M_t → M_r carrying an outbound payload to deliver
	// to the originator via M_r's public socket (preserves 5-tuple flow).
	OpReply uint8 = 0x02

	// FlowIDSize is the random per-flow correlation identifier length.
	FlowIDSize = 16

	// innerRelayForwardHeaderSize: 2 magic + 1 ver + 1 op + 16 flow + 16 IP + 2 port.
	innerRelayForwardHeaderSize = 2 + 1 + 1 + FlowIDSize + 16 + 2

	// innerRelayReplyHeaderSize: 2 magic + 1 ver + 1 op + 16 flow.
	innerRelayReplyHeaderSize = 2 + 1 + 1 + FlowIDSize
)

// FlowID is a per-relayed-flow random correlation ID. M_r generates it
// at OpForward time; M_t echoes it on every OpReply.
type FlowID [FlowIDSize]byte

// NewFlowID returns a cryptographically random FlowID.
func NewFlowID() FlowID {
	var f FlowID
	_, _ = rand.Read(f[:])
	return f
}

// String returns a hex representation (32 chars) suitable for logs.
func (f FlowID) String() string {
	const hex = "0123456789abcdef"
	out := make([]byte, FlowIDSize*2)
	for i, b := range f {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0xF]
	}
	return string(out)
}

var (
	ErrInnerRelayShort     = errors.New("inner-relay: packet too short")
	ErrInnerRelayMagic     = errors.New("inner-relay: bad magic")
	ErrInnerRelayVersion   = errors.New("inner-relay: unsupported version")
	ErrInnerRelayOp        = errors.New("inner-relay: unknown op")
)

// IsInnerRelay reports whether data starts with the inner-relay magic.
// Cheap discriminator suitable for the listener's hot path.
func IsInnerRelay(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return binary.BigEndian.Uint16(data[0:2]) == InnerRelayMagic
}

// EncodeInnerRelayForward wraps a payload in an op=1 forward frame.
// The originator's 5-tuple goes in the header so M_t can use it as the
// apparent source of msg1 — Noise's handshake state is keyed by remote
// address, so M_t must see the same address the originator presented
// to Fly's edge.
func EncodeInnerRelayForward(flowID FlowID, srcAddr *net.UDPAddr, payload []byte) []byte {
	out := make([]byte, innerRelayForwardHeaderSize+len(payload))
	binary.BigEndian.PutUint16(out[0:2], InnerRelayMagic)
	out[2] = InnerRelayVersion
	out[3] = OpForward
	copy(out[4:4+FlowIDSize], flowID[:])
	// Normalize to 16-byte IPv6 form so the wire layout is fixed regardless
	// of whether the originator was IPv4 or IPv6. IPv4 → ::ffff:a.b.c.d
	// (RFC 4291) so M_t can recover the IPv4 form via .To4() if needed.
	ipBytes := srcAddr.IP.To16()
	if ipBytes == nil {
		ipBytes = make([]byte, 16) // zero — undefined originator, dropped by M_t
	}
	copy(out[4+FlowIDSize:4+FlowIDSize+16], ipBytes)
	binary.BigEndian.PutUint16(out[4+FlowIDSize+16:4+FlowIDSize+16+2], uint16(srcAddr.Port))
	copy(out[innerRelayForwardHeaderSize:], payload)
	return out
}

// EncodeInnerRelayReply wraps a payload in an op=2 reply frame.
func EncodeInnerRelayReply(flowID FlowID, payload []byte) []byte {
	out := make([]byte, innerRelayReplyHeaderSize+len(payload))
	binary.BigEndian.PutUint16(out[0:2], InnerRelayMagic)
	out[2] = InnerRelayVersion
	out[3] = OpReply
	copy(out[4:4+FlowIDSize], flowID[:])
	copy(out[innerRelayReplyHeaderSize:], payload)
	return out
}

// DecodedInnerRelay carries the parsed fields of an inner-relay frame.
// SrcAddr is set on OpForward only (origin 5-tuple). FlowID is always
// present. Payload points into the original buffer; copy if retaining.
type DecodedInnerRelay struct {
	Op      uint8
	FlowID  FlowID
	SrcAddr *net.UDPAddr // op=1 only
	Payload []byte
}

// DecodeInnerRelay parses an inner-relay frame. The shape (op=1 vs
// op=2) determines the header length; the codec returns an error for
// unknown ops so callers can drop and rate-limit cleanly.
func DecodeInnerRelay(data []byte) (*DecodedInnerRelay, error) {
	if len(data) < innerRelayReplyHeaderSize {
		return nil, ErrInnerRelayShort
	}
	if binary.BigEndian.Uint16(data[0:2]) != InnerRelayMagic {
		return nil, ErrInnerRelayMagic
	}
	if data[2] != InnerRelayVersion {
		return nil, ErrInnerRelayVersion
	}
	op := data[3]
	dec := &DecodedInnerRelay{Op: op}
	copy(dec.FlowID[:], data[4:4+FlowIDSize])

	switch op {
	case OpReply:
		dec.Payload = data[innerRelayReplyHeaderSize:]
		return dec, nil

	case OpForward:
		if len(data) < innerRelayForwardHeaderSize {
			return nil, ErrInnerRelayShort
		}
		ipBytes := data[4+FlowIDSize : 4+FlowIDSize+16]
		port := binary.BigEndian.Uint16(data[4+FlowIDSize+16 : 4+FlowIDSize+16+2])
		ip := make(net.IP, 16)
		copy(ip, ipBytes)
		// Collapse IPv4-mapped form back to a 4-byte IP so reply writes
		// use the natural IPv4 path. RFC 4291 ::ffff:a.b.c.d → a.b.c.d.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		dec.SrcAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		dec.Payload = data[innerRelayForwardHeaderSize:]
		return dec, nil

	default:
		return nil, ErrInnerRelayOp
	}
}

// ── flow tables ──────────────────────────────────────────────────────
//
// The M_r-side table maps each FlowID to the originator's public
// 5-tuple, so OpReply frames can be unwrapped and written back to the
// originator from M_r's listener socket.
//
// The M_t-side table maps each originator-address (the synth source we
// injected the msg1 from) to the M_r relay address + FlowID, so the
// noise transport's outbound write can detect "this peer is relayed"
// and wrap the reply in OpReply instead of writing it via Fly's NAT.
//
// Both are bounded by a TTL — a session that goes idle for longer than
// flowTableTTL is GC'd, freeing the slot. Active sessions touch
// lastSeen on every packet so they don't expire.

const (
	// flowTableTTL is the idle window after which a relay flow is GC'd.
	// 5 minutes covers a normal keepalive cadence with margin; an
	// active session refreshes lastSeen on every relay packet.
	flowTableTTL = 5 * time.Minute

	// flowTableSweepInterval is how often the GC sweep runs. Cheap.
	flowTableSweepInterval = 30 * time.Second

	// flowTableMaxEntries caps each table size so a flood of bogus
	// FlowIDs can't blow memory. Sized for ~10x expected steady-state
	// cross-org peer count per machine — generous but bounded.
	flowTableMaxEntries = 4096
)

// rFlowEntry is the M_r-side per-flow record.
type rFlowEntry struct {
	srcAddr  *net.UDPAddr // originator's public 5-tuple
	lastSeen time.Time
}

// tFlowEntry is the M_t-side per-flow record.
type tFlowEntry struct {
	relayAddr *net.UDPAddr // M_r's 6PN address — where OpReply goes
	flowID    FlowID
	lastSeen  time.Time
}

// ── forwarder ────────────────────────────────────────────────────────

// ForwarderLookup resolves a target NodeID to the 6PN UDP address of
// the same-org machine that holds the target's listener session. Used
// only on M_r when receiving a routing-preamble msg1 destined for a
// non-local NodeID. Returns nil + ok=false if the target is unknown
// to the local directory; the caller drops the packet.
type ForwarderLookup func(target aether.NodeID) (intraOrgAddr *net.UDPAddr, ok bool)

// dropReason categorises drops on the forwarder hot path. Counters are
// atomic uint64s on IntraOrgForwarder; the plan's Testing §5 ("drop and
// recorded in counter") rests on these.
type dropReason int

const (
	dropPreambleMalformed   dropReason = iota // AE preamble decode failed
	dropTargetUnknown                         // ForwarderLookup returned (nil,false)
	dropInnerRelayMalformed                   // RL frame decode failed
	dropOpForwardNoSrc                        // OpForward with nil SrcAddr
	dropOpReplyStaleFlow                      // OpReply with FlowID not in R-table
	dropOpUnknown                             // RL frame with op != 1,2
	dropReasonCount
)

// IntraOrgForwarder owns the inner relay state for one NoiseTransport.
// Installed via NoiseTransport.SetForwarder; absent forwarder = the
// transport processes only locally-targeted preambled msg1 and ignores
// non-local targets (graceful degradation).
type IntraOrgForwarder struct {
	lookup   ForwarderLookup
	localNID aether.NodeID

	// M_r-side: flow_id → originator addr.
	rMu sync.RWMutex
	r   map[FlowID]*rFlowEntry

	// M_t-side: synth originator addr (string key) → relay record.
	tMu sync.RWMutex
	t   map[string]*tFlowEntry

	// Per-reason drop counters. Atomic so the hot path doesn't need a
	// lock and observers can read without contending the table mutexes.
	drops [dropReasonCount]uint64

	// Stopped via Close so the sweeper goroutine exits cleanly.
	stop chan struct{}
	once sync.Once
}

// NewIntraOrgForwarder builds a forwarder for one transport. localNID
// is the NodeID this transport listens for — routing preambles
// targeted at localNID bypass the lookup and dispatch locally.
func NewIntraOrgForwarder(localNID aether.NodeID, lookup ForwarderLookup) *IntraOrgForwarder {
	f := &IntraOrgForwarder{
		lookup:   lookup,
		localNID: localNID,
		r:        make(map[FlowID]*rFlowEntry),
		t:        make(map[string]*tFlowEntry),
		stop:     make(chan struct{}),
	}
	go f.sweepLoop()
	return f
}

// Close stops the GC sweeper and clears both flow tables. Safe to call
// multiple times. Purging the tables (vs. relying on process exit) lets
// callers Close a per-tenant transport during dynamic reload without
// leaking entries — the abandoned forwarder won't hold references.
func (f *IntraOrgForwarder) Close() {
	f.once.Do(func() {
		close(f.stop)
		f.rMu.Lock()
		f.r = make(map[FlowID]*rFlowEntry)
		f.rMu.Unlock()
		f.tMu.Lock()
		f.t = make(map[string]*tFlowEntry)
		f.tMu.Unlock()
	})
}

// recordDrop bumps the per-reason drop counter atomically. Safe from the
// hot read-path; observers can pull via Drops().
func (f *IntraOrgForwarder) recordDrop(reason dropReason) {
	if f == nil || reason < 0 || reason >= dropReasonCount {
		return
	}
	atomic.AddUint64(&f.drops[reason], 1)
}

// Drops returns a snapshot of the per-reason drop counters. Used by
// observability code (meshmon / monitoring handlers) to surface forwarder
// health without exposing the internal counter array.
func (f *IntraOrgForwarder) Drops() (preambleMalformed, targetUnknown, innerRelayMalformed, opForwardNoSrc, opReplyStaleFlow, opUnknown uint64) {
	if f == nil {
		return
	}
	preambleMalformed = atomic.LoadUint64(&f.drops[dropPreambleMalformed])
	targetUnknown = atomic.LoadUint64(&f.drops[dropTargetUnknown])
	innerRelayMalformed = atomic.LoadUint64(&f.drops[dropInnerRelayMalformed])
	opForwardNoSrc = atomic.LoadUint64(&f.drops[dropOpForwardNoSrc])
	opReplyStaleFlow = atomic.LoadUint64(&f.drops[dropOpReplyStaleFlow])
	opUnknown = atomic.LoadUint64(&f.drops[dropOpUnknown])
	return
}

// LocalNodeID reports the NodeID this forwarder is configured for.
// Listener integration uses this to decide local-vs-remote routing.
func (f *IntraOrgForwarder) LocalNodeID() aether.NodeID { return f.localNID }

// Lookup proxies to the configured lookup callback. Exposed so the
// listener path can resolve the target without holding internal state.
func (f *IntraOrgForwarder) Lookup(target aether.NodeID) (*net.UDPAddr, bool) {
	if f == nil || f.lookup == nil {
		return nil, false
	}
	return f.lookup(target)
}

// RegisterForwarded is called by M_r when it forwards an inbound
// preambled msg1 to M_t. It stores the (FlowID → originator) mapping
// so subsequent OpReply frames can be unwrapped and delivered back.
func (f *IntraOrgForwarder) RegisterForwarded(flowID FlowID, srcAddr *net.UDPAddr) {
	f.rMu.Lock()
	defer f.rMu.Unlock()
	if len(f.r) >= flowTableMaxEntries {
		f.evictOldestRLocked()
	}
	f.r[flowID] = &rFlowEntry{srcAddr: srcAddr, lastSeen: time.Now()}
}

// LookupForwarded returns the originator address for a FlowID and
// updates lastSeen. Used by M_r when it unwraps an OpReply from M_t.
// Returns nil if the FlowID is unknown (expired or never registered).
func (f *IntraOrgForwarder) LookupForwarded(flowID FlowID) *net.UDPAddr {
	f.rMu.Lock()
	defer f.rMu.Unlock()
	entry, ok := f.r[flowID]
	if !ok {
		return nil
	}
	entry.lastSeen = time.Now()
	return entry.srcAddr
}

// RegisterRelayed is called by M_t when it receives an OpForward and
// is about to inject the payload into the noise listener as if it
// came from synth_src. It records (synth_src → relay_addr, FlowID)
// so subsequent outbound writes to synth_src can be wrapped in
// OpReply and sent to M_r's relay socket.
func (f *IntraOrgForwarder) RegisterRelayed(synthSrc *net.UDPAddr, relayAddr *net.UDPAddr, flowID FlowID) {
	key := synthSrc.String()
	f.tMu.Lock()
	defer f.tMu.Unlock()
	if len(f.t) >= flowTableMaxEntries {
		f.evictOldestTLocked()
	}
	f.t[key] = &tFlowEntry{relayAddr: relayAddr, flowID: flowID, lastSeen: time.Now()}
}

// LookupRelayed returns the relay record for a destination address.
// Used by the noise transport's outbound write to detect relayed
// flows. Returns nil if the destination is not relayed (normal write
// proceeds).
func (f *IntraOrgForwarder) LookupRelayed(destAddr *net.UDPAddr) (*net.UDPAddr, FlowID, bool) {
	key := destAddr.String()
	f.tMu.Lock()
	defer f.tMu.Unlock()
	entry, ok := f.t[key]
	if !ok {
		return nil, FlowID{}, false
	}
	entry.lastSeen = time.Now()
	return entry.relayAddr, entry.flowID, true
}

// ── GC ───────────────────────────────────────────────────────────────

func (f *IntraOrgForwarder) sweepLoop() {
	ticker := time.NewTicker(flowTableSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-ticker.C:
			f.sweep()
		}
	}
}

func (f *IntraOrgForwarder) sweep() {
	cutoff := time.Now().Add(-flowTableTTL)
	f.rMu.Lock()
	for fid, e := range f.r {
		if e.lastSeen.Before(cutoff) {
			delete(f.r, fid)
		}
	}
	f.rMu.Unlock()
	f.tMu.Lock()
	for k, e := range f.t {
		if e.lastSeen.Before(cutoff) {
			delete(f.t, k)
		}
	}
	f.tMu.Unlock()
}

// evictOldestRLocked drops the single oldest entry. Caller holds rMu.
// LRU-ish without per-touch list maintenance — O(n) but only on the
// rare "table full" path; steady state stays cheap.
func (f *IntraOrgForwarder) evictOldestRLocked() {
	var oldKey FlowID
	var oldT time.Time
	first := true
	for k, e := range f.r {
		if first || e.lastSeen.Before(oldT) {
			oldKey, oldT, first = k, e.lastSeen, false
		}
	}
	if !first {
		delete(f.r, oldKey)
	}
}

func (f *IntraOrgForwarder) evictOldestTLocked() {
	var oldKey string
	var oldT time.Time
	first := true
	for k, e := range f.t {
		if first || e.lastSeen.Before(oldT) {
			oldKey, oldT, first = k, e.lastSeen, false
		}
	}
	if !first {
		delete(f.t, oldKey)
	}
}

// RTableSize reports the M_r-side table size. Test/observability only.
func (f *IntraOrgForwarder) RTableSize() int {
	f.rMu.RLock()
	defer f.rMu.RUnlock()
	return len(f.r)
}

// TTableSize reports the M_t-side table size.
func (f *IntraOrgForwarder) TTableSize() int {
	f.tMu.RLock()
	defer f.tMu.RUnlock()
	return len(f.t)
}
