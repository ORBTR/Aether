//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Forward-secret 0.5-RTT resumption key schedule (AE-C-01 fix).
//
// Pre-fix, resumption reinstalled the ORIGINAL session's transport keys at
// nonce 0 on every resume. The live session kept advancing those same keys
// (nonce 1,2,3…) while each resumed session restarted them at nonce 0 — so
// (key,nonce) pairs repeated between the original and every resume. For
// ChaCha20-Poly1305 that is catastrophic: identical keystream XORed with two
// plaintexts (recoverable by any passive eavesdropper) plus Poly1305 one-time
// key reuse (forgery).
//
// This schedule replaces that. Every resume performs a fresh ephemeral X25519
// exchange and mixes the DH shared secret with the ticket PSK, so each resumed
// session derives UNIQUE, FORWARD-SECRET traffic keys that share no (key,nonce)
// with the original session or any other resume — the TLS 1.3 psk_dhe_ke shape.
package noise

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	resumeEphPubSize    = 32 // X25519 public key
	resumeBinderSize    = 32 // HMAC-SHA256 PSK-possession binder
	resumeConfirmTagLen = 16 // AEAD tag proving the responder derived the keys
)

// Domain-separated HKDF info strings. The "v2" tag marks the forward-secret
// schedule so any future rotation of this key derivation is unambiguous.
var (
	resumeInfoI2R    = []byte("aether-resume-v2 i2r")
	resumeInfoR2I    = []byte("aether-resume-v2 r2i")
	resumeInfoBinder = []byte("aether-resume-v2 binder")
)

// canonicalResumePSK returns the resumption pre-shared secret in a
// perspective-independent order — i2r ‖ r2i (the initiator→responder key
// followed by the responder→initiator key) — so both peers produce identical
// bytes despite storing keys from mirrored perspectives:
//   - initiator feeds (i2r = its SendKey, r2i = its RecvKey)
//   - responder feeds (i2r = its RecvKey, r2i = its SendKey)
func canonicalResumePSK(i2r, r2i [32]byte) []byte {
	psk := make([]byte, 64)
	copy(psk[0:32], i2r[:])
	copy(psk[32:64], r2i[:])
	return psk
}

// deriveResumeKeys mixes the ticket PSK with the ephemeral DH shared secret,
// binds them to the exchange transcript, and expands two directional traffic
// keys. dh is X25519(ephLocalPriv, ephRemotePub) — the forward-secret input.
// opaque/ephIPub/ephRPub bind the transcript so tampering any wire field yields
// different keys (and the confirm-tag then fails). Both peers compute identical
// keyI2R/keyR2I.
func deriveResumeKeys(psk, dh, opaque, ephIPub, ephRPub []byte) (keyI2R, keyR2I [32]byte) {
	th := sha256.New()
	th.Write(opaque)
	th.Write(ephIPub)
	th.Write(ephRPub)
	transcript := th.Sum(nil)

	ikm := make([]byte, 0, len(psk)+len(dh))
	ikm = append(ikm, psk...)
	ikm = append(ikm, dh...)

	prk := hkdf.Extract(sha256.New, ikm, transcript)
	expandInto(prk, resumeInfoI2R, keyI2R[:])
	expandInto(prk, resumeInfoR2I, keyR2I[:])
	return keyI2R, keyR2I
}

func expandInto(prk, info, out []byte) {
	// hkdf.Expand over SHA-256 never returns short for a 32-byte read.
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, prk, info), out)
}

// resumeBinder computes the PSK-possession binder over the initiator's
// contribution, keyed by a PSK-ONLY key (no DH). The responder can therefore
// verify ticket possession BEFORE spending an X25519 op — cheap protection
// against forged/replayed tickets driving DH work. The MAC covers the prefix,
// the opaque ticket, and the initiator ephemeral so none can be swapped.
func resumeBinder(psk, opaque, ephIPub []byte) []byte {
	prk := hkdf.Extract(sha256.New, psk, nil)
	binderKey := make([]byte, 32)
	expandInto(prk, resumeInfoBinder, binderKey)

	mac := hmac.New(sha256.New, binderKey)
	mac.Write([]byte{resumePrefix})
	mac.Write(opaque)
	mac.Write(ephIPub)
	return mac.Sum(nil)
}

// resumeBinderValid re-derives and constant-time-compares the binder.
func resumeBinderValid(psk, opaque, ephIPub, got []byte) bool {
	if len(got) != resumeBinderSize {
		return false
	}
	return subtle.ConstantTimeCompare(resumeBinder(psk, opaque, ephIPub), got) == 1
}

// newResumeEphemeral generates a fresh X25519 keypair for a single resume.
func newResumeEphemeral() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// resumeDH computes the X25519 shared secret. crypto/ecdh rejects invalid and
// low-order peer keys (all-zero output), so a malicious ephemeral is refused.
func resumeDH(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pk)
}
