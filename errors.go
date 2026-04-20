/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"errors"
	"fmt"
)

// OpError wraps a transport operation error with context.
// Supports errors.Is/errors.As for matching.
type OpError struct {
	Op       string   // "dial", "accept", "send", "receive", "handshake", "relay"
	Protocol Protocol // which transport protocol
	NodeID   NodeID   // remote node (empty if not yet known)
	Err      error    // underlying error
}

func (e *OpError) Error() string {
	if e.NodeID != "" {
		return fmt.Sprintf("%s %s %s: %v", e.Protocol, e.Op, e.NodeID.Short(), e.Err)
	}
	return fmt.Sprintf("%s %s: %v", e.Protocol, e.Op, e.Err)
}

func (e *OpError) Unwrap() error { return e.Err }

// WrapOp creates an OpError wrapping err with operation context.
func WrapOp(op string, proto Protocol, nodeID NodeID, err error) error {
	if err == nil {
		return nil
	}
	return &OpError{Op: op, Protocol: proto, NodeID: nodeID, Err: err}
}

// Sentinel errors — use errors.Is() to check.
var (
	ErrSessionClosed   = errors.New("transport: session closed")
	ErrHandshakeFailed = errors.New("transport: handshake failed")
	ErrRateLimited     = errors.New("transport: rate limited")
	ErrTenantMismatch  = errors.New("transport: scope mismatch")
	ErrKeyRotation     = errors.New("transport: key rotation in progress")
	ErrTargetNotFound  = errors.New("transport: relay target not found")
	ErrTicketExpired   = errors.New("transport: session ticket expired")
	ErrTicketInvalid   = errors.New("transport: session ticket invalid")
)
