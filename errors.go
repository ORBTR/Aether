/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
	ErrSessionClosed     = errors.New("transport: session closed")
	ErrHandshakeFailed   = errors.New("transport: handshake failed")
	ErrRateLimited       = errors.New("transport: rate limited")
	ErrPartitionMismatch = errors.New("transport: scope mismatch")
	ErrKeyRotation       = errors.New("transport: key rotation in progress")
	ErrTargetNotFound    = errors.New("transport: relay target not found")
	ErrTicketExpired     = errors.New("transport: session ticket expired")
	ErrTicketInvalid     = errors.New("transport: session ticket invalid")

	// ErrStreamCapExhausted signals that an OpenStream call was
	// refused because the session's MaxConcurrentStreams cap was
	// reached. The session remains healthy — the caller should
	// either back off and retry once existing streams close, or
	// surface a per-stream error to its own caller. Closing the
	// whole session in response to this error is INCORRECT: this
	// is a transient backpressure signal, not a transport failure.
	//
	// Use errors.Is(err, aether.ErrStreamCapExhausted) to detect.
	// Callers that pool streams
	// should arm a brief backoff when this error fires — re-dialing
	// immediately produces a busy-loop of OpenStream → refuse →
	// retry.
	ErrStreamCapExhausted = errors.New("transport: stream cap exhausted")

	// ErrDuplicateStreamID signals that OpenStream was called with a
	// StreamID already live in the session's stream table — e.g. a pool
	// recycling a caller-assigned ID before the prior stream closed. The
	// pre-existing stream is left intact; there is no new stream to
	// return, so the caller must pick a fresh StreamID or close the prior
	// stream first. A NoiseSession also answers it for an ID whose stream
	// left on both CLOSEs a moment ago, whose ID opens again a few RTOs later
	// (reopenQuietRTOs in adapter), because the peer may still be writing its
	// CLOSE again. A transient caller-side signal, not a transport
	// failure — do NOT close the session in response.
	// Use errors.Is(err, aether.ErrDuplicateStreamID) to detect.
	ErrDuplicateStreamID = errors.New("transport: duplicate stream id")

	// ErrSessionWriteFailed signals that a byte-stream session could not write to
	// its transport: a non-temporary error, or a temporary one that outlasted the
	// session's retry. The transport carries the session's frames in one sequence
	// with no retransmit, so a frame not written is a frame lost and the next would
	// be misread; the session ends with this as its close reason (CloseErr), and Send
	// and Receive on its streams return it.
	// Use errors.Is(err, aether.ErrSessionWriteFailed) to detect.
	ErrSessionWriteFailed = errors.New("transport: session write failed")

	// ErrStreamCreditRefused signals that a stream was not admitted because
	// its receive credit does not fit what the session's admitted streams,
	// or every session to the same peer together, already hold against
	// their aggregate ceiling, or because its initial credit is above the
	// stream's own ceiling. OpenStream returns it before the stream exists;
	// a stream the peer opens past an aggregate ceiling is answered with
	// RESET(ResetRefused) and reaches no acceptor. Like
	// ErrStreamCapExhausted it is backpressure, not a transport failure:
	// the session stays up and the open may succeed once streams end.
	// Use errors.Is(err, aether.ErrStreamCreditRefused) to detect.
	ErrStreamCreditRefused = errors.New("transport: stream credit refused")

	// ErrStreamRefused signals that the peer answered this stream with
	// RESET(ResetRefused): it refused to admit it (its stream cap or its
	// aggregate credit ceiling), so nothing sent on it is delivered.
	// Send and Receive on such a stream return it, so the opener reads a
	// refusal as a refusal and not as an ordinary end.
	// Use errors.Is(err, aether.ErrStreamRefused) to detect.
	ErrStreamRefused = errors.New("transport: stream refused by peer")

	// ErrFECRepairMalformed signals an FEC_REPAIR payload that cannot be read or
	// does not fit the stream it arrived on: DecodeFECHeader and
	// reliability.StreamFEC return it, and adapter.NoiseSession's handleFECRepair
	// charges the peer for it and keeps nothing of the repair.
	ErrFECRepairMalformed = errors.New("transport: FEC repair malformed")

	// ErrFECLevelUnsupported signals a stream configuration whose FEC level is
	// outside the registry (reliability.FECLevel). adapter.NoiseSession's
	// OpenStream returns it before the stream exists, so a level this build cannot
	// run is refused and never read as no FEC.
	ErrFECLevelUnsupported = errors.New("transport: FEC level unsupported")

	// ErrStreamOverrun signals that a stream ended with messages it could not
	// deliver. On a byte-stream session (TCP, WebSocket, gRPC) the receiver's
	// delivery queue was full: the sender sent more bytes than the receiving
	// consumer had read and the queue holds, the bounds profile's stream credit
	// (flow.BoundsProfile.StreamCredit), or the session's queues together had
	// reached its session ceiling. On a Noise session the sender went past the
	// credit it holds. On either, what every session to one peer holds had reached
	// the profile's per-peer ceiling. Each way the receiver reset the stream with
	// RESET(ResetFlowCtrl) rather than drop a message unannounced: on the
	// receiver, Receive returns every message the queue held and then this
	// error; on the sender, Send and Receive return it once that RESET arrives.
	// The messages the sender sent after the last one the queue took are not
	// delivered. A receiver also returns it when messages it had queued on a
	// stream already ended were thrown away because their consumer did not read
	// them in time or a later message needed their room. It is a refusal
	// of the stream, not a transport failure: the session stays up.
	// Use errors.Is(err, aether.ErrStreamOverrun) to detect.
	ErrStreamOverrun = errors.New("transport: stream reset, receiver's delivery queue full")

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
// adapter implements CloseErrorReporter. Returns nil for a session that
// closed cleanly or is still open, for a session type without CloseErr,
// and for one whose adapter never calls SetCloseErr (QUICSession embeds
// BaseSession and records no close reason; NoiseSession and TCPSession,
// which WebSocketSession and GrpcSession embed, record theirs). Agnostic
// accessor — callers never need a type switch between
// NoiseSession/TCPSession/etc.
func SessionCloseErr(s Session) error {
	if r, ok := s.(CloseErrorReporter); ok {
		return r.CloseErr()
	}
	return nil
}
