//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randKey32(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

// TestAEC01_ResumeKeysAgreeAcrossPeers proves the forward-secret schedule is
// interoperable: initiator and responder — feeding mirrored ticket keys plus a
// real X25519 exchange — derive identical directional traffic keys. Without
// agreement the resumed session simply would not decrypt.
func TestAEC01_ResumeKeysAgreeAcrossPeers(t *testing.T) {
	i2r := randKey32(t)
	r2i := randKey32(t)
	opaque := make([]byte, 40)
	if _, err := rand.Read(opaque); err != nil {
		t.Fatal(err)
	}

	// Both sides compute the canonical PSK from mirrored perspectives:
	// initiator feeds (SendKey=i2r, RecvKey=r2i); responder feeds
	// (RecvKey=i2r, SendKey=r2i) — same argument order here, same bytes.
	pskInit := canonicalResumePSK(i2r, r2i)
	pskResp := canonicalResumePSK(i2r, r2i)
	if !bytes.Equal(pskInit, pskResp) {
		t.Fatal("canonical PSK differs across perspectives")
	}

	ephI, err := newResumeEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ephR, err := newResumeEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ephIPub := ephI.PublicKey().Bytes()
	ephRPub := ephR.PublicKey().Bytes()

	dhI, err := resumeDH(ephI, ephRPub)
	if err != nil {
		t.Fatal(err)
	}
	dhR, err := resumeDH(ephR, ephIPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dhI, dhR) {
		t.Fatal("X25519 shared secret disagreement")
	}

	iI2R, iR2I := deriveResumeKeys(pskInit, dhI, opaque, ephIPub, ephRPub)
	rI2R, rR2I := deriveResumeKeys(pskResp, dhR, opaque, ephIPub, ephRPub)
	if iI2R != rI2R || iR2I != rR2I {
		t.Fatal("initiator/responder derived different resume keys — would not interoperate")
	}
	if iI2R == iR2I {
		t.Fatal("the two directional keys are identical — must be distinct")
	}
}

// TestAEC01_ResumeKeysUniquePerResume is the core AE-C-01 property: every resume
// yields keys distinct from the raw ticket PSK AND from any other resume, so no
// (key,nonce) pair is ever reused. The pre-fix bug reinstalled the raw PSK keys
// at nonce 0 on every resume — catastrophic keystream + Poly1305 reuse.
func TestAEC01_ResumeKeysUniquePerResume(t *testing.T) {
	i2r := randKey32(t)
	r2i := randKey32(t)
	psk := canonicalResumePSK(i2r, r2i)
	opaque := []byte("opaque-ticket-blob-xxxxxxxxxxxxxxxxxxxxxx")

	derive := func() ([32]byte, [32]byte) {
		ephI, _ := newResumeEphemeral()
		ephR, _ := newResumeEphemeral()
		dh, _ := resumeDH(ephI, ephR.PublicKey().Bytes())
		return deriveResumeKeys(psk, dh, opaque, ephI.PublicKey().Bytes(), ephR.PublicKey().Bytes())
	}

	a1, a2 := derive()
	b1, b2 := derive()

	if a1 == b1 || a2 == b2 {
		t.Fatal("two resumes produced identical keys — nonce/keystream reuse (AE-C-01)")
	}
	if a1 == i2r || a1 == r2i || a2 == i2r || a2 == r2i {
		t.Fatal("a derived resume key equals a raw ticket key — original-session collision (AE-C-01)")
	}
	if b1 == i2r || b1 == r2i || b2 == i2r || b2 == r2i {
		t.Fatal("a derived resume key equals a raw ticket key — original-session collision (AE-C-01)")
	}
}

// TestAEC01_BinderRejectsTamper proves the PSK-possession binder authenticates
// the initiator contribution and rejects any tamper — so a peer holding a stolen
// opaque ticket but not its keys cannot forge a resume.
func TestAEC01_BinderRejectsTamper(t *testing.T) {
	psk := canonicalResumePSK(randKey32(t), randKey32(t))
	opaque := []byte("ticket-opaque")
	ephI, _ := newResumeEphemeral()
	ephIPub := ephI.PublicKey().Bytes()

	binder := resumeBinder(psk, opaque, ephIPub)
	if !resumeBinderValid(psk, opaque, ephIPub, binder) {
		t.Fatal("valid binder rejected")
	}

	badEph := append([]byte(nil), ephIPub...)
	badEph[0] ^= 0xFF
	if resumeBinderValid(psk, opaque, badEph, binder) {
		t.Fatal("binder accepted a tampered ephemeral")
	}
	if resumeBinderValid(psk, []byte("other-ticket"), ephIPub, binder) {
		t.Fatal("binder accepted a tampered opaque ticket")
	}
	otherPSK := canonicalResumePSK(randKey32(t), randKey32(t))
	if resumeBinderValid(otherPSK, opaque, ephIPub, binder) {
		t.Fatal("binder accepted the wrong PSK (attacker without the ticket keys)")
	}
}
