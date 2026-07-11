//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package migration

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// connIDFromByte builds a deterministic ConnectionID for tests.
func connIDFromByte(b byte) aether.ConnectionID {
	var id aether.ConnectionID
	for i := range id {
		id[i] = b
	}
	return id
}

// nonceFromIndex builds a distinct 8-byte nonce from an integer index.
func nonceFromIndex(i int) [8]byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(i))
	return n
}

func TestConstants(t *testing.T) {
	// Payload layout: [ConnID:8][Nonce:8][Timestamp:8][IP:16][Port:2][HMAC:32] = 74.
	if got := 8 + 8 + 8 + 16 + 2 + 32; got != MigrationPayloadSize {
		t.Fatalf("MigrationPayloadSize layout mismatch: field sum %d, const %d", got, MigrationPayloadSize)
	}
	if MigrationPayloadSize != 74 {
		t.Errorf("MigrationPayloadSize: got %d, want 74", MigrationPayloadSize)
	}
	// The exported alias must track the root-package constant.
	if HandshakeAddressMigration != aether.HandshakeAddressMigration {
		t.Errorf("HandshakeAddressMigration alias drifted from root constant")
	}
}

func TestEncodeMigrationPayload_Layout(t *testing.T) {
	connID := connIDFromByte(0xAB)
	key := []byte("session-key-0123456789")
	ip := net.IPv4(203, 0, 113, 7)
	const port uint16 = 51820

	before := time.Now()
	payload := EncodeMigrationPayload(connID, ip, port, key)
	after := time.Now()

	if len(payload) != MigrationPayloadSize {
		t.Fatalf("payload length: got %d, want %d", len(payload), MigrationPayloadSize)
	}

	// ConnectionID region.
	if !bytes.Equal(payload[0:8], connID[:]) {
		t.Errorf("ConnectionID region: got %x, want %x", payload[0:8], connID[:])
	}

	// Timestamp region must fall inside the encode window.
	tsNanos := binary.BigEndian.Uint64(payload[16:24])
	ts := time.Unix(0, int64(tsNanos))
	if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v outside encode window [%v,%v]", ts, before, after)
	}

	// IP region must be the IPv6-mapped form of the input.
	if !bytes.Equal(payload[24:40], ip.To16()) {
		t.Errorf("IP region: got %x, want %x", payload[24:40], ip.To16())
	}

	// Port region.
	if got := binary.BigEndian.Uint16(payload[40:42]); got != port {
		t.Errorf("port region: got %d, want %d", got, port)
	}

	// HMAC region must equal HMAC over the first 42 bytes.
	wantMAC := computeHMAC(payload[:42], key)
	if !bytes.Equal(payload[42:74], wantMAC) {
		t.Errorf("HMAC region does not match computeHMAC over payload[:42]")
	}
}

func TestEncodeMigrationPayload_UniqueNoncePerCall(t *testing.T) {
	connID := connIDFromByte(0x11)
	key := []byte("k")
	ip := net.IPv4(10, 0, 0, 1)

	// Same (connID, ip, port, key) must yield different payloads each call:
	// this is the replay-resistance property (fresh random nonce → new HMAC).
	a := EncodeMigrationPayload(connID, ip, 443, key)
	b := EncodeMigrationPayload(connID, ip, 443, key)

	if bytes.Equal(a[8:16], b[8:16]) {
		t.Errorf("nonce region identical across calls: %x", a[8:16])
	}
	if bytes.Equal(a[42:74], b[42:74]) {
		t.Errorf("HMAC region identical across calls despite unique nonce")
	}
	// ConnID, IP, port regions must still be stable.
	if !bytes.Equal(a[0:8], b[0:8]) || !bytes.Equal(a[24:42], b[24:42]) {
		t.Errorf("stable regions (connID/ip/port) unexpectedly differ")
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	key := []byte("round-trip-key")
	connID := connIDFromByte(0x5A)

	tests := []struct {
		name string
		ip   net.IP
		port uint16
	}{
		{"ipv4", net.IPv4(192, 168, 1, 100), 8080},
		{"ipv6", net.ParseIP("2001:db8::1"), 5000},
		{"port-zero", net.IPv4(127, 0, 0, 1), 0},
		{"port-max", net.IPv4(1, 1, 1, 1), 65535},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := EncodeMigrationPayload(connID, tc.ip, tc.port, key)

			gotID, nonce, ts, gotIP, gotPort, err := DecodeMigrationPayload(payload, key)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if gotID != connID {
				t.Errorf("connID: got %x, want %x", gotID, connID)
			}
			if !gotIP.Equal(tc.ip) {
				t.Errorf("ip: got %v, want %v", gotIP, tc.ip)
			}
			if gotPort != tc.port {
				t.Errorf("port: got %d, want %d", gotPort, tc.port)
			}
			// Decoded timestamp should be very recent.
			if age := time.Since(ts); age < 0 || age > 5*time.Second {
				t.Errorf("decoded timestamp age out of range: %v", age)
			}
			// Nonce must be non-zero (crypto/rand fill).
			if nonce == ([8]byte{}) {
				t.Errorf("nonce decoded as all-zero")
			}
		})
	}
}

func TestDecodeMigrationPayload_TooShort(t *testing.T) {
	key := []byte("k")
	for _, n := range []int{0, 1, MigrationPayloadSize - 1} {
		if _, _, _, _, _, err := DecodeMigrationPayload(make([]byte, n), key); err == nil {
			t.Errorf("len %d: expected error, got nil", n)
		}
	}
}

func TestDecodeMigrationPayload_ExtraTrailingBytesOK(t *testing.T) {
	key := []byte("k")
	connID := connIDFromByte(0x22)
	payload := EncodeMigrationPayload(connID, net.IPv4(8, 8, 8, 8), 53, key)

	// Trailing bytes beyond the fixed layout must not affect validation,
	// since HMAC is computed over payload[:42] only.
	extended := append(payload, 0xDE, 0xAD, 0xBE, 0xEF)
	gotID, _, _, gotIP, gotPort, err := DecodeMigrationPayload(extended, key)
	if err != nil {
		t.Fatalf("decode of extended payload failed: %v", err)
	}
	if gotID != connID || !gotIP.Equal(net.IPv4(8, 8, 8, 8)) || gotPort != 53 {
		t.Errorf("extended-payload decode returned wrong fields")
	}
}

func TestDecodeMigrationPayload_WrongKey(t *testing.T) {
	connID := connIDFromByte(0x33)
	payload := EncodeMigrationPayload(connID, net.IPv4(10, 0, 0, 5), 1234, []byte("correct-key"))

	if _, _, _, _, _, err := DecodeMigrationPayload(payload, []byte("wrong-key")); err == nil {
		t.Fatalf("expected HMAC failure with wrong key, got nil")
	}
}

func TestDecodeMigrationPayload_Tampered(t *testing.T) {
	key := []byte("tamper-key")
	connID := connIDFromByte(0x44)
	payload := EncodeMigrationPayload(connID, net.IPv4(172, 16, 0, 1), 9000, key)

	// Flip a bit in the authenticated port region — HMAC must reject it.
	tampered := append([]byte(nil), payload...)
	tampered[41] ^= 0x01
	if _, _, _, _, _, err := DecodeMigrationPayload(tampered, key); err == nil {
		t.Errorf("expected HMAC failure after tampering port byte, got nil")
	}
}

func TestEncodeMigrationPayload_NilIP(t *testing.T) {
	key := []byte("nil-ip-key")
	connID := connIDFromByte(0x55)

	payload := EncodeMigrationPayload(connID, nil, 7, key)
	_, _, _, gotIP, gotPort, err := DecodeMigrationPayload(payload, key)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if gotPort != 7 {
		t.Errorf("port: got %d, want 7", gotPort)
	}
	// A nil input IP must serialize as a 16-byte all-zero address.
	if len(gotIP) != 16 {
		t.Fatalf("ip length: got %d, want 16", len(gotIP))
	}
	for i, b := range gotIP {
		if b != 0 {
			t.Errorf("nil IP not zeroed at byte %d: %x", i, b)
		}
	}
}

func TestValidateMigration_Success(t *testing.T) {
	m := NewMigrator()
	key := []byte("validate-key")
	connID := connIDFromByte(0x66)
	ip := net.IPv4(198, 51, 100, 22)
	const port uint16 = 4321

	payload := EncodeMigrationPayload(connID, ip, port, key)
	if err := m.ValidateMigration(connID, ip, port, key, payload); err != nil {
		t.Fatalf("ValidateMigration: unexpected error %v", err)
	}

	state, ok := m.GetMigration(connID)
	if !ok {
		t.Fatalf("GetMigration: migration not recorded")
	}
	if state.ConnectionID != connID {
		t.Errorf("state.ConnectionID: got %x, want %x", state.ConnectionID, connID)
	}
	if state.Complete {
		t.Errorf("state.Complete should be false immediately after validate")
	}
	if state.ValidatedAt.IsZero() {
		t.Errorf("state.ValidatedAt should be set")
	}
	udp, ok := state.NewAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("state.NewAddr: got %T, want *net.UDPAddr", state.NewAddr)
	}
	if !udp.IP.Equal(ip) {
		t.Errorf("NewAddr.IP: got %v, want %v", udp.IP, ip)
	}
	if udp.Port != int(port) {
		t.Errorf("NewAddr.Port: got %d, want %d", udp.Port, port)
	}
}

func TestValidateMigration_ConnIDMismatch(t *testing.T) {
	m := NewMigrator()
	key := []byte("mismatch-key")
	encoded := connIDFromByte(0x77)
	other := connIDFromByte(0x88)
	ip := net.IPv4(10, 10, 10, 10)

	// Payload is validly signed for `encoded`, but caller claims `other`.
	payload := EncodeMigrationPayload(encoded, ip, 80, key)
	if err := m.ValidateMigration(other, ip, 80, key, payload); err == nil {
		t.Fatalf("expected ConnectionID mismatch error, got nil")
	}
	if _, ok := m.GetMigration(other); ok {
		t.Errorf("mismatched migration must not be recorded")
	}
}

func TestValidateMigration_WrongKey(t *testing.T) {
	m := NewMigrator()
	connID := connIDFromByte(0x99)
	ip := net.IPv4(10, 0, 0, 9)
	payload := EncodeMigrationPayload(connID, ip, 80, []byte("real-key"))

	if err := m.ValidateMigration(connID, ip, 80, []byte("bad-key"), payload); err == nil {
		t.Fatalf("expected decode/HMAC error with wrong key, got nil")
	}
	if _, ok := m.GetMigration(connID); ok {
		t.Errorf("failed migration must not be recorded")
	}
}

func TestValidateMigration_Expired(t *testing.T) {
	m := NewMigrator()
	key := []byte("expiry-key")
	connID := connIDFromByte(0xA1)
	ip := net.IPv4(10, 1, 2, 3)

	// Build a payload whose timestamp is well beyond the TTL, re-signing so
	// the HMAC stays valid (isolating the TTL check from the HMAC check).
	payload := EncodeMigrationPayload(connID, ip, 22, key)
	oldTS := time.Now().Add(-2 * MigrationTokenTTL).UnixNano()
	binary.BigEndian.PutUint64(payload[16:24], uint64(oldTS))
	copy(payload[42:74], computeHMAC(payload[:42], key))

	err := m.ValidateMigration(connID, ip, 22, key, payload)
	if err != ErrMigrationExpired {
		t.Fatalf("expected ErrMigrationExpired, got %v", err)
	}
	if _, ok := m.GetMigration(connID); ok {
		t.Errorf("expired migration must not be recorded")
	}
}

func TestValidateMigration_FutureTimestampExpired(t *testing.T) {
	m := NewMigrator()
	key := []byte("future-key")
	connID := connIDFromByte(0xA2)
	ip := net.IPv4(10, 4, 5, 6)

	// A timestamp in the future yields a negative age, which the validator
	// also treats as expired (clock-skew / forged-future guard).
	payload := EncodeMigrationPayload(connID, ip, 22, key)
	futureTS := time.Now().Add(time.Hour).UnixNano()
	binary.BigEndian.PutUint64(payload[16:24], uint64(futureTS))
	copy(payload[42:74], computeHMAC(payload[:42], key))

	if err := m.ValidateMigration(connID, ip, 22, key, payload); err != ErrMigrationExpired {
		t.Fatalf("expected ErrMigrationExpired for future timestamp, got %v", err)
	}
}

func TestValidateMigration_Replay(t *testing.T) {
	m := NewMigrator()
	key := []byte("replay-key")
	connID := connIDFromByte(0xB0)
	ip := net.IPv4(203, 0, 113, 9)

	payload := EncodeMigrationPayload(connID, ip, 1000, key)

	// First acceptance succeeds and remembers the nonce.
	if err := m.ValidateMigration(connID, ip, 1000, key, payload); err != nil {
		t.Fatalf("first validate: unexpected error %v", err)
	}
	// Replaying the exact same (still-fresh) payload must be rejected.
	if err := m.ValidateMigration(connID, ip, 1000, key, payload); err != ErrMigrationReplay {
		t.Fatalf("replay: expected ErrMigrationReplay, got %v", err)
	}
}

func TestCompleteMigration(t *testing.T) {
	m := NewMigrator()
	key := []byte("complete-key")
	connID := connIDFromByte(0xC0)
	ip := net.IPv4(10, 0, 0, 200)

	payload := EncodeMigrationPayload(connID, ip, 6000, key)
	if err := m.ValidateMigration(connID, ip, 6000, key, payload); err != nil {
		t.Fatalf("validate: %v", err)
	}

	m.CompleteMigration(connID)
	state, ok := m.GetMigration(connID)
	if !ok {
		t.Fatalf("migration missing after complete")
	}
	if !state.Complete {
		t.Errorf("state.Complete: got false, want true")
	}

	// Completing an unknown connID must be a safe no-op.
	m.CompleteMigration(connIDFromByte(0xFF))
	if _, ok := m.GetMigration(connIDFromByte(0xFF)); ok {
		t.Errorf("no-op complete must not create a migration")
	}
}

func TestGetMigration_NotFound(t *testing.T) {
	m := NewMigrator()
	state, ok := m.GetMigration(connIDFromByte(0x01))
	if ok || state != nil {
		t.Errorf("GetMigration on empty migrator: got (%v,%v), want (nil,false)", state, ok)
	}
}

func TestPrune(t *testing.T) {
	m := NewMigrator()
	key := []byte("prune-key")

	fresh := connIDFromByte(0xD1)
	stale := connIDFromByte(0xD2)
	done := connIDFromByte(0xD3)
	ip := net.IPv4(10, 9, 8, 7)

	for _, id := range []aether.ConnectionID{fresh, stale, done} {
		p := EncodeMigrationPayload(id, ip, 500, key)
		if err := m.ValidateMigration(id, ip, 500, key, p); err != nil {
			t.Fatalf("validate %x: %v", id, err)
		}
	}

	// Age out the "stale" entry via its state pointer.
	staleState, _ := m.GetMigration(stale)
	staleState.ValidatedAt = time.Now().Add(-time.Hour)

	// Mark "done" complete (but keep it fresh) — Prune drops it regardless of age.
	m.CompleteMigration(done)

	m.Prune(30 * time.Minute)

	if _, ok := m.GetMigration(fresh); !ok {
		t.Errorf("fresh migration was incorrectly pruned")
	}
	if _, ok := m.GetMigration(stale); ok {
		t.Errorf("stale migration was not pruned")
	}
	if _, ok := m.GetMigration(done); ok {
		t.Errorf("completed migration was not pruned")
	}
}

func TestRecordNonce_FIFOEviction(t *testing.T) {
	m := NewMigrator()

	// Fill the seen-set exactly to capacity.
	for i := 0; i < MigrationSeenCacheSize; i++ {
		m.recordNonceLocked(nonceFromIndex(i))
	}
	if len(m.seenOrder) != MigrationSeenCacheSize {
		t.Fatalf("seenOrder length after fill: got %d, want %d", len(m.seenOrder), MigrationSeenCacheSize)
	}
	if _, ok := m.seenNonces[nonceFromIndex(0)]; !ok {
		t.Fatalf("oldest nonce should still be present at capacity")
	}

	// One more insertion evicts the oldest (FIFO) and stays capped.
	m.recordNonceLocked(nonceFromIndex(MigrationSeenCacheSize))
	if len(m.seenOrder) != MigrationSeenCacheSize {
		t.Errorf("seenOrder length after overflow: got %d, want %d (capped)", len(m.seenOrder), MigrationSeenCacheSize)
	}
	if len(m.seenNonces) != MigrationSeenCacheSize {
		t.Errorf("seenNonces size after overflow: got %d, want %d", len(m.seenNonces), MigrationSeenCacheSize)
	}
	if _, ok := m.seenNonces[nonceFromIndex(0)]; ok {
		t.Errorf("oldest nonce should have been evicted")
	}
	if _, ok := m.seenNonces[nonceFromIndex(MigrationSeenCacheSize)]; !ok {
		t.Errorf("newest nonce should be present after insertion")
	}
}
