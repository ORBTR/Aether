//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestNoiseRoundTrip tests a simple request/response exchange.
func TestNoiseRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows: shared-socket UDP handshake dispatch is timing-sensitive (see Concern #G13)")
	}
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := serverPriv.Public().(ed25519.PublicKey)
	serverNodeID, _ := aether.NewNodeID(serverPub)

	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientNodeID, _ := aether.NewNodeID(clientPub)

	testNetKey := "test-network-key"
	serverTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  serverPriv,
		LocalNode:   serverNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{testNetKey},
	})
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}

	// Use a longer timeout for debugging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	// Note: Don't defer listener.Close() yet - let's see if it affects things

	serverAddr := listener.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Server echoes back
	serverReady := make(chan struct{})
	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		t.Log("Server: waiting for Accept...")
		serverSession, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		t.Logf("Server: accepted session from %s", serverSession.RemoteAddr())
		close(serverReady)

		// Echo loop
		for {
			recvCtx, recvCancel := context.WithTimeout(ctx, 5*time.Second)
			data, err := serverSession.Receive(recvCtx)
			recvCancel()
			if err != nil {
				// Don't log expected shutdown errors
				if ctx.Err() == nil {
					t.Logf("Server: Receive error: %v", err)
				}
				serverSession.Close()
				return
			}
			t.Logf("Server: received %d bytes: %q", len(data), data)
			if err := serverSession.Send(ctx, data); err != nil {
				if ctx.Err() == nil {
					t.Logf("Server: Send error: %v", err)
				}
				serverSession.Close()
				return
			}
			t.Logf("Server: response sent to %s", serverSession.RemoteAddr())
		}
	}()

	clientTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  clientPriv,
		LocalNode:   clientNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{testNetKey},
	})
	if err != nil {
		t.Fatalf("Failed to create client transport: %v", err)
	}

	// Client must Listen before Dial — Dial uses the shared listener socket
	clientListener, err := clientTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("Client Listen failed: %v", err)
	}
	defer clientListener.Close()

	// Allow listener goroutines to start processing before dialing.
	// On Windows, UDP goroutine scheduling can be delayed.
	time.Sleep(50 * time.Millisecond)

	// Retry dial up to 3 times — shared-socket handshake on localhost
	// can lose the first packet if the server readloop hasn't scheduled.
	var clientSession aether.Connection
	for attempt := 0; attempt < 3; attempt++ {
		t.Logf("Client: dialing %s (attempt %d)...", serverAddr, attempt+1)
		dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
		clientSession, err = clientTransport.Dial(dialCtx, aether.Target{
			Address: serverAddr,
			NodeID:  serverNodeID,
		})
		dialCancel()
		if err == nil {
			break
		}
		t.Logf("Client: dial attempt %d failed: %v", attempt+1, err)
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Dial failed after 3 attempts: %v", err)
	}
	defer clientSession.Close()
	t.Logf("Client: dial complete, local addr: %s", clientSession.(*aether.BaseConnection).Conn.LocalAddr())

	// Wait for server to be ready
	select {
	case <-serverReady:
		t.Log("Server is ready")
	case err := <-serverErr:
		t.Fatalf("Server accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server ready")
	}

	payload := []byte("ping")

	t.Log("Client: sending ping...")
	if err := clientSession.Send(ctx, payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	t.Log("Client: send complete, waiting for response...")

	resp, err := clientSession.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	t.Logf("Client: received response: %q", resp)

	if string(resp) != string(payload) {
		t.Errorf("Expected %q, got %q", payload, resp)
	}

	// Clean shutdown: cancel context and wait for server goroutine
	cancel()
	listener.Close()
	<-serverDone
}
