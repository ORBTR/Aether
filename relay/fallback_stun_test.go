//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package relay

import (
	"context"
	"errors"
	"testing"

	aether "github.com/ORBTR/aether"
)

// TestFallbackDialer_NoSTUNComposedDetectsNoNATType: this package links no STUN
// implementation, so a dialer given no client detects no NAT type and says why,
// and Dial takes the path it takes when detection fails.
func TestFallbackDialer_NoSTUNComposedDetectsNoNATType(t *testing.T) {
	d := NewFallbackDialer(FallbackConfig{STUNConfig: aether.DefaultSTUNConfig()})
	if natType, err := d.detectNATType(context.Background()); !errors.Is(err, aether.ErrSTUNNotComposed) || natType != aether.NATUnknown {
		t.Fatalf("detectNATType: %v, %v; want NATUnknown and aether.ErrSTUNNotComposed", natType, err)
	}
}
