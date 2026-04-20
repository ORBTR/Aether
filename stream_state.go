/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"sync"
)

// StreamState represents the lifecycle state of an Aether stream.
type StreamState uint8

const (
	StreamIdle       StreamState = iota // before OPEN sent/received
	StreamOpen                          // OPEN exchanged, data can flow
	StreamHalfClosed                    // local FIN sent, waiting for peer FIN
	StreamClosed                        // both FINs exchanged or RESET received
)

// String returns a human-readable state name.
func (s StreamState) String() string {
	switch s {
	case StreamIdle:
		return "idle"
	case StreamOpen:
		return "open"
	case StreamHalfClosed:
		return "half-closed"
	case StreamClosed:
		return "closed"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// StreamEvent represents an event that triggers a state transition.
type StreamEvent uint8

const (
	EventSendOpen  StreamEvent = iota // local: sent OPEN frame
	EventRecvOpen                     // remote: received OPEN frame
	EventSendFIN                      // local: sent FIN (Close called)
	EventRecvFIN                      // remote: received FIN
	EventSendReset                    // local: sent RESET
	EventRecvReset                    // remote: received RESET
	EventSendData                     // local: sent DATA (implicit open with SYN)
	EventRecvData                     // remote: received DATA (implicit open with SYN)
)

// String returns a human-readable event name.
func (e StreamEvent) String() string {
	switch e {
	case EventSendOpen:
		return "send-open"
	case EventRecvOpen:
		return "recv-open"
	case EventSendFIN:
		return "send-fin"
	case EventRecvFIN:
		return "recv-fin"
	case EventSendReset:
		return "send-reset"
	case EventRecvReset:
		return "recv-reset"
	case EventSendData:
		return "send-data"
	case EventRecvData:
		return "recv-data"
	default:
		return fmt.Sprintf("unknown(%d)", e)
	}
}

// StreamStateMachine manages the lifecycle transitions of a single Aether stream.
// Thread-safe — all transitions are serialized.
type StreamStateMachine struct {
	mu       sync.Mutex
	state    StreamState
	localFIN bool // we sent FIN
	peerFIN  bool // peer sent FIN
}

// NewStreamStateMachine creates a state machine in the Idle state.
func NewStreamStateMachine() *StreamStateMachine {
	return &StreamStateMachine{state: StreamIdle}
}

// State returns the current stream state.
func (s *StreamStateMachine) State() StreamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// IsOpen returns true if the stream can send or receive data.
func (s *StreamStateMachine) IsOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == StreamOpen || s.state == StreamHalfClosed
}

// CanSend returns true if the local side can still send data.
func (s *StreamStateMachine) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == StreamOpen && !s.localFIN
}

// CanReceive returns true if the local side can still receive data.
func (s *StreamStateMachine) CanReceive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return (s.state == StreamOpen || s.state == StreamHalfClosed) && !s.peerFIN
}

// Transition applies an event and returns an error if the transition is invalid.
func (s *StreamStateMachine) Transition(event StreamEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case StreamIdle:
		switch event {
		case EventSendOpen, EventSendData:
			s.state = StreamOpen
			return nil
		case EventRecvOpen, EventRecvData:
			s.state = StreamOpen
			return nil
		case EventRecvReset, EventSendReset:
			s.state = StreamClosed
			return nil
		default:
			return fmt.Errorf("aether: invalid event %s in state %s", event, s.state)
		}

	case StreamOpen:
		switch event {
		case EventSendFIN:
			s.localFIN = true
			if s.peerFIN {
				s.state = StreamClosed
			} else {
				s.state = StreamHalfClosed
			}
			return nil
		case EventRecvFIN:
			s.peerFIN = true
			if s.localFIN {
				s.state = StreamClosed
			}
			return nil
		case EventSendReset, EventRecvReset:
			s.state = StreamClosed
			return nil
		case EventSendData, EventRecvData:
			return nil // data in open state is normal
		default:
			return fmt.Errorf("aether: invalid event %s in state %s", event, s.state)
		}

	case StreamHalfClosed:
		switch event {
		case EventRecvFIN:
			s.peerFIN = true
			s.state = StreamClosed
			return nil
		case EventRecvData:
			return nil // peer can still send in half-closed (local closed, peer open)
		case EventSendReset, EventRecvReset:
			s.state = StreamClosed
			return nil
		default:
			return fmt.Errorf("aether: invalid event %s in state %s", event, s.state)
		}

	case StreamClosed:
		// No transitions from closed
		return fmt.Errorf("aether: stream is closed, cannot process event %s", event)

	default:
		return fmt.Errorf("aether: unknown state %d", s.state)
	}
}
