//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package grpc

import (
	"testing"

	"github.com/ORBTR/aether"
)

func TestGrpcTransportConfig(t *testing.T) {
	cfg := GrpcTransportConfig{
		LocalNode:  "test-node-id",
		PrivateKey: make([]byte, 64),
		ListenAddr: ":9000",
	}

	gt := NewGrpcTransport(cfg)
	if gt == nil {
		t.Fatal("NewGrpcTransport returned nil")
	}
	if gt.localNode != cfg.LocalNode {
		t.Errorf("localNode mismatch: got %s, want %s", gt.localNode, cfg.LocalNode)
	}
	if gt.listenAddr != cfg.ListenAddr {
		t.Errorf("listenAddr mismatch: got %s, want %s", gt.listenAddr, cfg.ListenAddr)
	}
	if gt.incoming == nil {
		t.Error("incoming channel should be initialized")
	}
}

func TestGrpcMetadataConstants(t *testing.T) {
	// Verify metadata constants are set correctly
	if MetadataNodeID == "" {
		t.Error("MetadataNodeID should not be empty")
	}
	if MetadataSignature == "" {
		t.Error("MetadataSignature should not be empty")
	}
	// Verify they follow gRPC metadata naming convention (lowercase)
	if MetadataNodeID != "x-hstles-nodeid" {
		t.Errorf("MetadataNodeID should be lowercase, got %s", MetadataNodeID)
	}
}

func TestGrpcSessionInterface(t *testing.T) {
	// Verify GrpcSession implements aether.Connection
	var _ aether.Connection = (*GrpcSession)(nil)
}

func TestGrpcListenerInterface(t *testing.T) {
	// Verify GrpcListener implements aether.Listener
	var _ aether.Listener = (*GrpcListener)(nil)
}

func TestNewGrpcTransportDefaults(t *testing.T) {
	cfg := GrpcTransportConfig{
		LocalNode: "node-1",
	}

	gt := NewGrpcTransport(cfg)

	// Empty listen addr should be handled
	if gt.listenAddr != "" {
		t.Errorf("Default listenAddr should be empty, got %s", gt.listenAddr)
	}

	// Incoming channel should have buffer
	if cap(gt.incoming) != 32 {
		t.Errorf("incoming channel capacity should be 32, got %d", cap(gt.incoming))
	}
}
