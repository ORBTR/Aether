/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package pb

import (
	"testing"
	"time"
)

func TestRPCRequestRoundTrip(t *testing.T) {
	original := &RPCRequest{
		Id:        "req-123",
		Handler:   "auth.Enroll",
		Payload:   []byte(`{"token":"abc"}`),
		Context:   map[string]string{"scope": "t1", "trace": "xyz"},
		TimeoutNs: int64(5 * time.Second),
		SessionId: "sess-456",
		TraceId:   "trace-789",
		Hops:      2,
	}

	data, err := MarshalRequest(original)
	if err != nil {
		t.Fatalf("MarshalRequest: %v", err)
	}

	decoded, err := UnmarshalRequest(data)
	if err != nil {
		t.Fatalf("UnmarshalRequest: %v", err)
	}

	if decoded.Id != original.Id {
		t.Errorf("Id: got %q, want %q", decoded.Id, original.Id)
	}
	if decoded.Handler != original.Handler {
		t.Errorf("Handler: got %q, want %q", decoded.Handler, original.Handler)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload: got %q, want %q", decoded.Payload, original.Payload)
	}
	if decoded.Context["scope"] != "t1" || decoded.Context["trace"] != "xyz" {
		t.Errorf("Context: got %v, want %v", decoded.Context, original.Context)
	}
	if decoded.TimeoutNs != original.TimeoutNs {
		t.Errorf("TimeoutNs: got %v, want %v", decoded.TimeoutNs, original.TimeoutNs)
	}
	if decoded.SessionId != original.SessionId {
		t.Errorf("SessionId: got %q, want %q", decoded.SessionId, original.SessionId)
	}
	if decoded.TraceId != original.TraceId {
		t.Errorf("TraceId: got %q, want %q", decoded.TraceId, original.TraceId)
	}
	if decoded.Hops != original.Hops {
		t.Errorf("Hops: got %d, want %d", decoded.Hops, original.Hops)
	}
}

func TestRPCRequestRoutingFields(t *testing.T) {
	original := &RPCRequest{
		Id:           "req-route",
		Handler:      "identity.GetUser",
		TargetNodeId: "node-abc",
		RouteList:    []string{"node-b", "node-c", "node-abc"},
		RequestNonce: "nonce-xyz",
		Deadline:     time.Now().UnixNano(),
		Hops:         3,
	}

	data, err := MarshalRequest(original)
	if err != nil {
		t.Fatalf("MarshalRequest: %v", err)
	}

	decoded, err := UnmarshalRequest(data)
	if err != nil {
		t.Fatalf("UnmarshalRequest: %v", err)
	}

	if decoded.TargetNodeId != original.TargetNodeId {
		t.Errorf("TargetNodeId: got %q, want %q", decoded.TargetNodeId, original.TargetNodeId)
	}
	if len(decoded.RouteList) != 3 {
		t.Fatalf("RouteList len: got %d, want 3", len(decoded.RouteList))
	}
	if decoded.RequestNonce != original.RequestNonce {
		t.Errorf("RequestNonce: got %q, want %q", decoded.RequestNonce, original.RequestNonce)
	}
	if decoded.Deadline != original.Deadline {
		t.Errorf("Deadline: got %d, want %d", decoded.Deadline, original.Deadline)
	}
}

func TestRPCResponseRoundTrip(t *testing.T) {
	original := &RPCResponse{
		Id:        "resp-123",
		Success:   true,
		Payload:   []byte(`{"status":"ok"}`),
		Error:     "",
		LatencyNs: int64(150 * time.Millisecond),
		Metadata:  map[string]string{"node": "abc"},
	}

	data, err := MarshalResponse(original)
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}

	decoded, err := UnmarshalResponse(data)
	if err != nil {
		t.Fatalf("UnmarshalResponse: %v", err)
	}

	if decoded.Id != original.Id {
		t.Errorf("Id: got %q, want %q", decoded.Id, original.Id)
	}
	if decoded.Success != original.Success {
		t.Errorf("Success: got %v, want %v", decoded.Success, original.Success)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload: got %q, want %q", decoded.Payload, original.Payload)
	}
	if decoded.LatencyNs != original.LatencyNs {
		t.Errorf("LatencyNs: got %v, want %v", decoded.LatencyNs, original.LatencyNs)
	}
	if decoded.Metadata["node"] != "abc" {
		t.Errorf("Metadata: got %v, want %v", decoded.Metadata, original.Metadata)
	}
}

func TestReadWriteMessage(t *testing.T) {
	req := &RPCRequest{
		Id:      "msg-test",
		Handler: "ping",
		Payload: []byte("hello"),
	}

	data, err := MarshalRequest(req)
	if err != nil {
		t.Fatalf("MarshalRequest: %v", err)
	}

	// Verify size is reasonable
	if len(data) > MaxMessageSize {
		t.Errorf("Message too large: %d bytes", len(data))
	}
	if len(data) == 0 {
		t.Error("Message is empty")
	}
}
