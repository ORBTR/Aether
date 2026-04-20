/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package client

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ORBTR/aether/rpc/pb"
	aether "github.com/ORBTR/aether"
)

// Client provides RPC-over-VL1 client functionality using binary protobuf-style serialization.
// Wire format: [4-byte length (BigEndian)][binary message]
type Client struct {
	session aether.Connection
	logger  *log.Logger
	mu      sync.Mutex
}

// NewClient creates a new RPC client over an existing VL1 session
func NewClient(session aether.Connection) *Client {
	return &Client{
		session: session,
		logger:  log.Default(),
	}
}

// RPCResponse represents the result of an RPC call (client-facing type).
type RPCResponse struct {
	ID       string                 `json:"id"`
	Success  bool                   `json:"success"`
	Payload  []byte                 `json:"payload"`
	Error    string                 `json:"error"`
	Latency  time.Duration          `json:"latency"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Call makes a synchronous RPC call using binary serialization over VL1.
func (c *Client) Call(ctx context.Context, handler string, payload []byte, metadata map[string]string) (*RPCResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate request ID if not provided
	reqID := fmt.Sprintf("rpc-%d", time.Now().UnixNano())

	// Create protobuf RPC request
	req := &pb.RPCRequest{
		Id:      reqID,
		Handler: handler,
		Payload: payload,
		Context: metadata,
	}

	// Write request
	if err := c.writeMessage(ctx, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read response with timeout
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	readCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	resp, err := c.readMessage(readCtx)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Convert to client-facing response type
	clientResp := &RPCResponse{
		ID:      resp.Id,
		Success: resp.Success,
		Payload: resp.Payload,
		Error:   resp.Error,
		Latency: time.Duration(resp.LatencyNs),
	}

	// Convert metadata
	if resp.Metadata != nil {
		clientResp.Metadata = make(map[string]interface{})
		for k, v := range resp.Metadata {
			clientResp.Metadata[k] = v
		}
	}

	return clientResp, nil
}

// writeMessage writes a protobuf message to the session.
func (c *Client) writeMessage(ctx context.Context, req *pb.RPCRequest) error {
	buf, err := pb.MarshalRequest(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	return c.session.Send(ctx, buf)
}

// readMessage reads a protobuf message from the session.
func (c *Client) readMessage(ctx context.Context) (*pb.RPCResponse, error) {
	buf, err := c.session.Receive(ctx)
	if err != nil {
		return nil, err
	}
	return pb.UnmarshalResponse(buf)
}

// Close closes the underlying VL1 session
func (c *Client) Close() error {
	return c.session.Close()
}
