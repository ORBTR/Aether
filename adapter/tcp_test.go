//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

func TestTCPSession_OpenStreamAndSendReceive(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession := NewTCPSession(clientConn, "vl1_client_test_node_id_abcdef", "vl1_server_test_node_id_ghijkl", aether.ProtoTCP, aether.DefaultSessionOptions())
	serverSession := NewTCPSession(serverConn, "vl1_server_test_node_id_ghijkl", "vl1_client_test_node_id_abcdef", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer clientSession.Close()
	defer serverSession.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client opens stream
	clientStream, err := clientSession.OpenStream(ctx, aether.StreamConfig{
		StreamID:    1,
		Reliability: aether.ReliableOrdered,
		Priority:    128,
	})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Server accepts stream
	serverStream, err := serverSession.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	if serverStream.StreamID() != 1 {
		t.Errorf("server stream ID: got %d, want %d", serverStream.StreamID(), 1)
	}

	// Client sends data
	if err := clientStream.Send(ctx, []byte("hello aether")); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Server receives (needs time for scheduler + write loop)
	time.Sleep(50 * time.Millisecond)
	data, err := serverStream.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(data) != "hello aether" {
		t.Errorf("received: got %q, want %q", data, "hello aether")
	}
}

func TestTCPSession_InterfaceCompliance(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session := NewTCPSession(clientConn, "vl1_test", "vl1_remote", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer session.Close()

	if session.LocalNodeID() != "vl1_test" {
		t.Errorf("LocalNodeID: got %s", session.LocalNodeID())
	}
	if session.RemoteNodeID() != "vl1_remote" {
		t.Errorf("RemoteNodeID: got %s", session.RemoteNodeID())
	}
	if session.IsClosed() {
		t.Error("should not be closed")
	}
	if session.SessionKey() != nil {
		t.Error("TCP should not have session key (TLS provides encryption)")
	}
	if session.CongestionWindow() != 0 {
		t.Error("TCP should return 0 congestion window (native congestion)")
	}
	if session.Protocol() != aether.ProtoTCP {
		t.Errorf("Protocol: got %v, want ProtoTCP", session.Protocol())
	}
}

func TestTCPSession_Close(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	session := NewTCPSession(clientConn, "vl1_test", "vl1_remote", aether.ProtoTCP, aether.DefaultSessionOptions())
	session.Close()

	if !session.IsClosed() {
		t.Error("should be closed after Close()")
	}
}

func TestTCPSession_ObserveMetrics(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession := NewTCPSession(clientConn, "vl1_client_test_node_id_abcdef", "vl1_server_test_node_id_ghijkl", aether.ProtoTCP, aether.DefaultSessionOptions())
	serverSession := NewTCPSession(serverConn, "vl1_server_test_node_id_ghijkl", "vl1_client_test_node_id_abcdef", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer clientSession.Close()
	defer serverSession.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open stream and send 3 messages
	clientStream, err := clientSession.OpenStream(ctx, aether.StreamConfig{
		StreamID: 50, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	serverStream, err := serverSession.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = serverStream // server side receives

	for i := 0; i < 3; i++ {
		if err := clientStream.Send(ctx, []byte("observe-test")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// Wait for delivery
	time.Sleep(100 * time.Millisecond)

	// Drain the server recvCh
	for i := 0; i < 3; i++ {
		if _, err := serverStream.Receive(ctx); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
	}

	// Check observe metrics on the SERVER session (receiver side)
	metrics := serverSession.Metrics()
	if metrics.StreamObserve == nil {
		t.Fatal("StreamObserve should not be nil")
	}
	obs, ok := metrics.StreamObserve[50]
	if !ok {
		t.Fatalf("no observe data for stream 50, keys: %v", metrics.StreamObserve)
	}
	if obs.PacketsReceived != 3 {
		t.Fatalf("packets: got %d, want 3", obs.PacketsReceived)
	}
	if obs.BytesReceived != 36 { // 3 * len("observe-test") = 3 * 12
		t.Fatalf("bytes: got %d, want 36", obs.BytesReceived)
	}
	if obs.GapCount != 0 {
		t.Fatalf("gaps: got %d, want 0 (in-order TCP delivery)", obs.GapCount)
	}
}

func TestStreamConn_ReadWrite(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession := NewTCPSession(clientConn, "vl1_client", "vl1_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	serverSession := NewTCPSession(serverConn, "vl1_server", "vl1_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer clientSession.Close()
	defer serverSession.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientStream, _ := clientSession.OpenStream(ctx, aether.StreamConfig{
		StreamID: 100, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	serverStream, _ := serverSession.AcceptStream(ctx)

	// Wrap in StreamConn for net.Conn compatibility
	clientSC := NewStreamConn(clientStream)
	serverSC := NewStreamConn(serverStream)
	defer clientSC.Close()
	defer serverSC.Close()

	// Write via StreamConn
	_, err := clientSC.Write([]byte("via StreamConn"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Read via StreamConn
	buf := make([]byte, 100)
	n, err := serverSC.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "via StreamConn" {
		t.Errorf("read: got %q", buf[:n])
	}
}
