/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// generateTestEd25519 is a tiny wrapper that fits a signature our
// tests like to pass in. Real code uses ed25519.GenerateKey directly.
func generateTestEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	return ed25519.GenerateKey(rand.Reader)
}

// ed25519Sign signs msg with priv.
func ed25519Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}
