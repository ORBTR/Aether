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

	// ErrSessionStuck signals that a session has persistently been unable
	// to make forward progress (e.g. sustained Consume timeouts on the
	// send path while in-flight frames sit unACKed) long past any
	// recovery horizon. The session closes itself with this error so the
	// owning connection manager can treat the current path as broken and
	// downgrade to the next protocol grade (Noise-UDP → QUIC → WebSocket
	// → gRPC → TLS) rather than thrashing forever on a black-holed path.
	//
	// Use SessionCloseErr(session) or errors.Is(...) to detect.
	ErrSessionStuck = errors.New("transport: session stuck (no forward progress)")
)

// CloseErrorReporter is the optional interface implemented by Session
// adapters that can report the reason their session closed. Use
// SessionCloseErr as the accessor — it tolerates adapters that don't
// implement this interface by returning nil.
type CloseErrorReporter interface {
	// CloseErr returns the error the session was closed with, or nil
	// if it closed cleanly (or is still open).
	CloseErr() error
}

// SessionCloseErr returns the close-reason error for sessions whose
// adapter implements CloseErrorReporter. Returns nil for adapters that
// don't track this (QUIC, WebSocket currently) and for sessions that
// closed cleanly. Agnostic accessor — callers never need a type switch
// between NoiseSession/TCPSession/etc.
func SessionCloseErr(s Session) error {
	if r, ok := s.(CloseErrorReporter); ok {
		return r.CloseErr()
	}
	return nil
}
