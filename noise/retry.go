//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

// Handshake amplification mitigation — "Retry token" pattern (S3).
//
// The Noise XX handshake replies to a small msg1 (~5 bytes header + Curve25519
// ephemeral) with a much larger msg2 (~280 bytes including the responder's
// signed NodeInfo). Without source-address validation, an attacker can spoof
// arbitrary source IPs and use the listener as a ~7× UDP amplifier.
//
// The fix mirrors QUIC's stateless retry: on first contact from an
// unvalidated source, the responder does NOT compute Noise state. Instead
// it returns a small `RETRY` packet containing an HMAC-bound cookie that
// only the legitimate (non-spoofed) source can echo back. The second
// attempt — with the cookie — passes source validation and triggers the
// full handshake.
//
// Wire format of a RETRY packet (sent in response to first-time msg1):
//   [retryPrefix:1=0xFE][nonce:8][expiryUnixSec:8][hmac:32]   = 49 bytes
//
// Wire format of a retry-bearing initiator msg1:
//   [retryPrefix:1=0xFE][nonce:8][expiryUnixSec:8][hmac:32][original-msg1...]
//
// The responder validates: HMAC matches secretKey over (sourceIP||nonce||
// expiryUnixSec); expiry not yet reached. If valid, the inner msg1 is
// processed normally — costing the same as a first contact, but only for
// validated sources.

const (
	// retryPrefix marks a RETRY packet (responder→initiator) and a
	// retry-bearing handshake initiation (initiator→responder).
	// Chosen to not collide with STUN (0x00–0x3F), QUIC (0x40–0xBF),
	// dial-nonce prefix (0xFD), or Noise CRC32 fingerprints (which are
	// random over the full byte range — collision risk handled by HMAC).
	retryPrefix byte = 0xFE

	retryNonceSize  = 8
	retryExpirySize = 8
	retryHMACSize   = 32

	// retryHeaderSize is the wire size of a bare RETRY packet (no inner msg1).
	retryHeaderSize = 1 + retryNonceSize + retryExpirySize + retryHMACSize

	// RetryTokenTTL bounds how long a cookie is valid. Long enough for
	// a normal initiator round-trip; short enough that an attacker can't
	// stockpile cookies to amortise.
	RetryTokenTTL = 30 * time.Second
)

// retryGuard issues and validates source-validation cookies.
type retryGuard struct {
	secret [32]byte // HMAC key — random per-process, regenerated on restart
}

func newRetryGuard() *retryGuard {
	g := &retryGuard{}
	if _, err := rand.Read(g.secret[:]); err != nil {
		// Process-wide randomness failure — surface immediately rather
		// than ship a guard that can't authenticate cookies.
		panic("noise: rand.Read failed for retry guard secret: " + err.Error())
	}
	return g
}

// IssueToken builds a RETRY packet bound to the given source address.
// The token is valid for RetryTokenTTL from `now`.
func (g *retryGuard) IssueToken(addr net.Addr, now time.Time) []byte {
	out := make([]byte, retryHeaderSize)
	out[0] = retryPrefix
	if _, err := rand.Read(out[1 : 1+retryNonceSize]); err != nil {
		panic("noise: rand.Read failed for retry token nonce: " + err.Error())
	}
	expiry := now.Add(RetryTokenTTL).Unix()
	binary.BigEndian.PutUint64(out[1+retryNonceSize:1+retryNonceSize+retryExpirySize], uint64(expiry))

	mac := g.computeHMAC(addr, out[1:1+retryNonceSize], expiry)
	copy(out[1+retryNonceSize+retryExpirySize:], mac)
	return out
}

// HasRetryPrefix reports whether the packet begins with the retry marker.
// Cheap byte-test used by the listener before any allocation.
func HasRetryPrefix(pkt []byte) bool {
	return len(pkt) >= 1 && pkt[0] == retryPrefix
}

// ValidateAndStrip checks the retry token at the start of pkt against
// addr. Returns (innerMsg1, true) on valid token (caller proceeds with
// the wrapped Noise msg1) or (nil, false) on invalid/expired/short.
func (g *retryGuard) ValidateAndStrip(pkt []byte, addr net.Addr, now time.Time) ([]byte, bool) {
	if len(pkt) < retryHeaderSize {
		return nil, false
	}
	if pkt[0] != retryPrefix {
		return nil, false
	}
	nonce := pkt[1 : 1+retryNonceSize]
	expiryBytes := pkt[1+retryNonceSize : 1+retryNonceSize+retryExpirySize]
	mac := pkt[1+retryNonceSize+retryExpirySize : retryHeaderSize]

	expiry := int64(binary.BigEndian.Uint64(expiryBytes))
	if now.Unix() > expiry {
		return nil, false // expired cookie
	}

	expected := g.computeHMAC(addr, nonce, expiry)
	if !hmac.Equal(mac, expected) {
		return nil, false
	}
	return pkt[retryHeaderSize:], true
}

// computeHMAC is HMAC-SHA256(secret, sourceIP || nonce || expirySec).
// The IP (not IP+port) is bound so the cookie is unforgeable against
// spoofed sources but resilient to NAT port drift between the two
// initiator round-trips.
func (g *retryGuard) computeHMAC(addr net.Addr, nonce []byte, expiry int64) []byte {
	var ipBytes []byte
	if u, ok := addr.(*net.UDPAddr); ok {
		ipBytes = u.IP.To16()
	}
	if ipBytes == nil {
		ipBytes = []byte(addr.String())
	}
	mac := hmac.New(sha256.New, g.secret[:])
	mac.Write(ipBytes)
	mac.Write(nonce)
	var expBuf [8]byte
	binary.BigEndian.PutUint64(expBuf[:], uint64(expiry))
	mac.Write(expBuf[:])
	return mac.Sum(nil)
}
