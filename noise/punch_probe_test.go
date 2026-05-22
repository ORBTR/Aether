/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// TestPunchProbe verifies PunchProbe sends its probe burst from the live
// listening socket to the target address, and that a probe never errors
// the way a missing listener does.
func TestPunchProbe(t *testing.T) {
	pub, priv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  priv,
		LocalNode:   nodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{"test-network-key"},
	})
	if err != nil {
		t.Fatalf("create transport: %v", err)
	}

	// Probing before Listen must fail clearly rather than panic.
	if err := tr.PunchProbe(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); err == nil {
		t.Fatal("PunchProbe before Listen should fail")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Stand-in peer: a plain UDP socket that the probe should reach.
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("peer socket: %v", err)
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	if err := tr.PunchProbe(ctx, peerAddr); err != nil {
		t.Fatalf("PunchProbe to live peer failed: %v", err)
	}

	// At least one probe datagram must have landed on the peer socket.
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer received no probe datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], punchProbePayload) {
		t.Fatalf("probe payload = %q, want %q", buf[:n], punchProbePayload)
	}
}
