//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// ─── codec round-trip ────────────────────────────────────────────────

func TestInnerRelay_ForwardRoundTrip_IPv4(t *testing.T) {
	flowID := NewFlowID()
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 42), Port: 51234}
	payload := []byte("noise msg1 placeholder bytes")

	wire := EncodeInnerRelayForward(flowID, src, payload)
	if !IsInnerRelay(wire) {
		t.Fatal("IsInnerRelay false on freshly encoded forward")
	}

	dec, err := DecodeInnerRelay(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec.Op != OpForward {
		t.Fatalf("Op = %d, want %d", dec.Op, OpForward)
	}
	if dec.FlowID != flowID {
		t.Fatalf("FlowID mismatch")
	}
	if dec.SrcAddr.IP.To4() == nil {
		t.Fatalf("IPv4 origin decoded as non-IPv4: %s", dec.SrcAddr.IP)
	}
	if !dec.SrcAddr.IP.Equal(src.IP) {
		t.Fatalf("SrcAddr.IP %s != %s", dec.SrcAddr.IP, src.IP)
	}
	if dec.SrcAddr.Port != src.Port {
		t.Fatalf("SrcAddr.Port %d != %d", dec.SrcAddr.Port, src.Port)
	}
	if !bytes.Equal(dec.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestInnerRelay_ForwardRoundTrip_IPv6(t *testing.T) {
	flowID := NewFlowID()
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 41641}
	payload := []byte("v6 payload")

	wire := EncodeInnerRelayForward(flowID, src, payload)
	dec, err := DecodeInnerRelay(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.SrcAddr.IP.Equal(src.IP) {
		t.Fatalf("v6 SrcAddr.IP %s != %s", dec.SrcAddr.IP, src.IP)
	}
	if dec.SrcAddr.Port != src.Port {
		t.Fatalf("v6 SrcAddr.Port mismatch")
	}
	if !bytes.Equal(dec.Payload, payload) {
		t.Fatal("v6 payload mismatch")
	}
}

func TestInnerRelay_ReplyRoundTrip(t *testing.T) {
	flowID := NewFlowID()
	payload := []byte("noise msg2 placeholder")
	wire := EncodeInnerRelayReply(flowID, payload)

	dec, err := DecodeInnerRelay(wire)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Op != OpReply {
		t.Fatalf("Op = %d, want %d", dec.Op, OpReply)
	}
	if dec.FlowID != flowID {
		t.Fatal("FlowID mismatch")
	}
	if dec.SrcAddr != nil {
		t.Fatalf("OpReply must not carry SrcAddr (got %v)", dec.SrcAddr)
	}
	if !bytes.Equal(dec.Payload, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestInnerRelay_RejectsShort(t *testing.T) {
	for _, n := range []int{0, 1, 5, innerRelayReplyHeaderSize - 1} {
		buf := make([]byte, n)
		if n >= 2 {
			buf[0], buf[1] = 0x52, 0x4C // magic — but truncated body
		}
		if _, err := DecodeInnerRelay(buf); !errors.Is(err, ErrInnerRelayShort) {
			t.Fatalf("len=%d err=%v, want ErrInnerRelayShort", n, err)
		}
	}
}

func TestInnerRelay_RejectsForwardWithReplyLength(t *testing.T) {
	// A buffer with op=Forward but only the reply-header size present
	// must be rejected — the forward op needs the full src_IP/src_port.
	buf := make([]byte, innerRelayReplyHeaderSize)
	buf[0], buf[1] = 0x52, 0x4C
	buf[2] = InnerRelayVersion
	buf[3] = OpForward
	if _, err := DecodeInnerRelay(buf); !errors.Is(err, ErrInnerRelayShort) {
		t.Fatalf("err=%v, want ErrInnerRelayShort", err)
	}
}

func TestInnerRelay_RejectsWrongMagic(t *testing.T) {
	buf := make([]byte, innerRelayForwardHeaderSize)
	buf[0], buf[1] = 0x41, 0x45 // routing-preamble magic — wrong
	if _, err := DecodeInnerRelay(buf); !errors.Is(err, ErrInnerRelayMagic) {
		t.Fatalf("err=%v, want ErrInnerRelayMagic", err)
	}
	if IsInnerRelay(buf) {
		t.Fatal("IsInnerRelay false-positive on routing-preamble magic")
	}
}

func TestInnerRelay_RejectsUnknownVersion(t *testing.T) {
	flowID := NewFlowID()
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	wire := EncodeInnerRelayForward(flowID, src, []byte("x"))
	wire[2] = 0xEE
	if _, err := DecodeInnerRelay(wire); !errors.Is(err, ErrInnerRelayVersion) {
		t.Fatalf("err=%v, want ErrInnerRelayVersion", err)
	}
}

func TestInnerRelay_RejectsUnknownOp(t *testing.T) {
	flowID := NewFlowID()
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	wire := EncodeInnerRelayForward(flowID, src, []byte("x"))
	wire[3] = 0xFE
	if _, err := DecodeInnerRelay(wire); !errors.Is(err, ErrInnerRelayOp) {
		t.Fatalf("err=%v, want ErrInnerRelayOp", err)
	}
}

// Discriminator check: the existing preambles must not be mistaken for
// inner relay. If any of these match IsInnerRelay we have a magic
// collision and the listener path will misroute packets.
func TestInnerRelay_DiscriminatorVsOtherPreambles(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"tenant-preamble magic TP", []byte{0x54, 0x50, 0x00, 0x00}},
		{"routing-preamble magic AE", []byte{0x41, 0x45, 0x01, 0x00}},
		{"raw bytes 0x00", []byte{0x00, 0x00, 0x00, 0x00}},
		{"raw bytes 0xFF", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, c := range cases {
		if IsInnerRelay(c.data) {
			t.Fatalf("%s: false-positive on IsInnerRelay", c.name)
		}
	}
}

// ─── forwarder flow tables ───────────────────────────────────────────

func newTestForwarder(t *testing.T, lookup ForwarderLookup) (*IntraOrgForwarder, aether.NodeID) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nid, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatal(err)
	}
	f := NewIntraOrgForwarder(nid, lookup)
	t.Cleanup(f.Close)
	return f, nid
}

func TestForwarder_RTable_RoundTrip(t *testing.T) {
	f, _ := newTestForwarder(t, nil)
	flowID := NewFlowID()
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 50001}
	f.RegisterForwarded(flowID, src)
	if got := f.LookupForwarded(flowID); got == nil || !got.IP.Equal(src.IP) || got.Port != src.Port {
		t.Fatalf("LookupForwarded returned %v, want %v", got, src)
	}
}

func TestForwarder_RTable_UnknownFlowID(t *testing.T) {
	f, _ := newTestForwarder(t, nil)
	if got := f.LookupForwarded(NewFlowID()); got != nil {
		t.Fatalf("unknown FlowID returned %v, want nil", got)
	}
}

func TestForwarder_TTable_RoundTrip(t *testing.T) {
	f, _ := newTestForwarder(t, nil)
	synth := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 50001}
	relay := &net.UDPAddr{IP: net.ParseIP("fdaa::1"), Port: 41641}
	flowID := NewFlowID()
	f.RegisterRelayed(synth, relay, flowID)

	gotRelay, gotFlow, ok := f.LookupRelayed(synth)
	if !ok {
		t.Fatal("LookupRelayed reported not relayed")
	}
	if !gotRelay.IP.Equal(relay.IP) || gotRelay.Port != relay.Port {
		t.Fatalf("relay addr mismatch: %v vs %v", gotRelay, relay)
	}
	if gotFlow != flowID {
		t.Fatal("FlowID mismatch")
	}

	if _, _, ok := f.LookupRelayed(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9}); ok {
		t.Fatal("LookupRelayed returned true for unregistered addr")
	}
}

func TestForwarder_Lookup(t *testing.T) {
	hit := &net.UDPAddr{IP: net.ParseIP("fdaa::1"), Port: 41641}
	var calls int32
	var localID aether.NodeID
	f, lid := newTestForwarder(t, func(target aether.NodeID) (*net.UDPAddr, bool) {
		atomic.AddInt32(&calls, 1)
		if target == localID {
			return hit, true
		}
		return nil, false
	})
	localID = lid
	if got, ok := f.Lookup(localID); !ok || got != hit {
		t.Fatalf("Lookup(local) = (%v, %v), want (%v, true)", got, ok, hit)
	}
	if got, ok := f.Lookup("vl1_other_____________________"); ok || got != nil {
		t.Fatalf("Lookup(other) = (%v, %v), want (nil, false)", got, ok)
	}
	if c := atomic.LoadInt32(&calls); c != 2 {
		t.Fatalf("lookup calls = %d, want 2", c)
	}
}

func TestForwarder_NilSafeLookup(t *testing.T) {
	var nilF *IntraOrgForwarder
	if got, ok := nilF.Lookup("vl1_x"); ok || got != nil {
		t.Fatalf("nil forwarder Lookup = (%v, %v), want (nil, false)", got, ok)
	}
}

func TestForwarder_DropCountersAndCloseClearsTables(t *testing.T) {
	f, _ := newTestForwarder(t, nil)

	// Seed both tables so we can verify Close clears them.
	flowID := NewFlowID()
	f.RegisterForwarded(flowID, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})
	f.RegisterRelayed(
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2},
		&net.UDPAddr{IP: net.ParseIP("fdaa::1"), Port: 41641},
		NewFlowID(),
	)
	if f.RTableSize() == 0 || f.TTableSize() == 0 {
		t.Fatal("seed failed")
	}

	// Bump every drop reason once.
	f.recordDrop(dropPreambleMalformed)
	f.recordDrop(dropTargetUnknown)
	f.recordDrop(dropInnerRelayMalformed)
	f.recordDrop(dropOpForwardNoSrc)
	f.recordDrop(dropOpReplyStaleFlow)
	f.recordDrop(dropOpUnknown)

	preMal, tgtUnk, irMal, opNoSrc, opStale, opUnk := f.Drops()
	if preMal != 1 || tgtUnk != 1 || irMal != 1 || opNoSrc != 1 || opStale != 1 || opUnk != 1 {
		t.Fatalf("drop counters: preMal=%d tgtUnk=%d irMal=%d opNoSrc=%d opStale=%d opUnk=%d (each should be 1)",
			preMal, tgtUnk, irMal, opNoSrc, opStale, opUnk)
	}

	// Close should empty both tables — important for dynamic-reload paths
	// where the abandoned forwarder must not retain references.
	f.Close()
	if got := f.RTableSize(); got != 0 {
		t.Fatalf("RTableSize after Close = %d, want 0 (Close must purge)", got)
	}
	if got := f.TTableSize(); got != 0 {
		t.Fatalf("TTableSize after Close = %d, want 0 (Close must purge)", got)
	}

	// Idempotent.
	f.Close()

	// recordDrop on nil receiver must not panic — guard for safety.
	var nilF *IntraOrgForwarder
	nilF.recordDrop(dropPreambleMalformed)
}

func TestRoutingPreamble_RejectsUnknownFlagBits(t *testing.T) {
	// Manually craft a routing preamble with a non-zero flags byte —
	// future-flag forward-compat: decoders must reject any unknown bit.
	raw := EncodeRoutingPreamble(aether.NodeID("vl1_aaaaaaaaaaaaaaaaaaaaaaaaaa"))
	raw[3] = 0x01 // any non-zero value
	if _, _, err := DecodeRoutingPreamble(raw); !errors.Is(err, ErrRoutingPreambleFlags) {
		t.Fatalf("decoded with unknown flag bit: err=%v want ErrRoutingPreambleFlags", err)
	}
}

func TestRoutingPreamble_PanicsOnOverlongNodeID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("EncodeRoutingPreamble must panic on NodeID > 30 bytes; no panic observed")
		}
	}()
	overlong := aether.NodeID("vl1_this_string_is_well_beyond_30_bytes_long_xxxxx")
	EncodeRoutingPreamble(overlong)
}

func TestForwarder_CapEvictsOldest(t *testing.T) {
	// Force the LRU-ish eviction by inserting cap+1 entries with
	// strictly-increasing lastSeen, then verify the OLDEST one is gone.
	f, _ := newTestForwarder(t, nil)
	// Pre-fill: directly write entries with controlled lastSeen so the
	// test isn't a race against the wall clock.
	f.rMu.Lock()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < flowTableMaxEntries; i++ {
		var fid FlowID
		fid[0] = byte(i)
		fid[1] = byte(i >> 8)
		f.r[fid] = &rFlowEntry{
			srcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i&0xff)), Port: i},
			lastSeen: base.Add(time.Duration(i) * time.Second),
		}
	}
	f.rMu.Unlock()

	// Insertion at cap triggers evict-oldest.
	fid := NewFlowID()
	f.RegisterForwarded(fid, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 99})
	if got := f.RTableSize(); got != flowTableMaxEntries {
		t.Fatalf("RTableSize after evict = %d, want %d", got, flowTableMaxEntries)
	}
	// The lowest-key (oldest by lastSeen) should be gone.
	var zero FlowID // FlowID{0,0,…}
	if f.LookupForwarded(zero) != nil {
		t.Fatal("oldest entry (FlowID{0,…}) survived eviction")
	}
}
