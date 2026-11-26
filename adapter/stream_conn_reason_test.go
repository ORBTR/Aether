//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// hookedStream is an aether.Stream whose Receive and Send wait for their
// context to end and then run afterEnd before they return the context's
// error. A test uses afterEnd to act in the window between the deadline
// ending a call and the Read or Write that made it reading why it ended.
type hookedStream struct {
	afterEnd func()
}

func (s *hookedStream) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	s.afterEnd()
	return nil, ctx.Err()
}

func (s *hookedStream) Send(ctx context.Context, _ []byte) error {
	<-ctx.Done()
	s.afterEnd()
	return ctx.Err()
}

func (s *hookedStream) StreamID() uint64               { return 11 }
func (s *hookedStream) Close() error                   { return nil }
func (s *hookedStream) Reset(aether.ResetReason) error { return nil }
func (s *hookedStream) SetPriority(uint8, uint64)      {}
func (s *hookedStream) Config() aether.StreamConfig    { return aether.StreamConfig{} }
func (s *hookedStream) IsOpen() bool                   { return true }
func (s *hookedStream) Conn() net.Conn                 { return NewStreamConn(s) }

// A Read or a Write the deadline ended returns os.ErrDeadlineExceeded as a
// net.Error timeout even when a deadline setter runs before it has returned.
// yamux and the gossip codec set the next exchange's deadline from another
// goroutine and tell a timeout from a broken stream by that error, so a
// setter landing in the window must not turn the timeout into the bare
// context error of the cancelled call.
func TestStreamConn_ADeadlineSetterDoesNotChangeWhyACallEnded(t *testing.T) {
	setters := map[string]func(*StreamConn){
		"cleared":       func(c *StreamConn) { _ = c.SetDeadline(time.Time{}) },
		"moved later":   func(c *StreamConn) { _ = c.SetDeadline(time.Now().Add(time.Hour)) },
		"read cleared":  func(c *StreamConn) { _ = c.SetReadDeadline(time.Time{}) },
		"write cleared": func(c *StreamConn) { _ = c.SetWriteDeadline(time.Time{}) },
	}
	for name, set := range setters {
		for _, dir := range []string{"Read", "Write"} {
			t.Run(dir+"/"+name, func(t *testing.T) {
				stream := &hookedStream{}
				conn := NewStreamConn(stream)
				stream.afterEnd = func() { set(conn) }
				if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
					t.Fatalf("SetDeadline: %v", err)
				}
				var err error
				if dir == "Read" {
					_, err = conn.Read(make([]byte, 8))
				} else {
					_, err = conn.Write([]byte("x"))
				}
				if !errors.Is(err, os.ErrDeadlineExceeded) || !timedOut(err) {
					t.Fatalf("%s the deadline ended returned %v, want os.ErrDeadlineExceeded as a net.Error timeout", dir, err)
				}
			})
		}
	}
}

// Close still wins over a deadline that ended the same call first: a call
// that returns after Close reports net.ErrClosed.
func TestStreamConn_CloseAfterTheDeadlineEndedACallReportsClosed(t *testing.T) {
	for _, dir := range []string{"Read", "Write"} {
		t.Run(dir, func(t *testing.T) {
			stream := &hookedStream{}
			conn := NewStreamConn(stream)
			stream.afterEnd = func() { _ = conn.Close() }
			if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			var err error
			if dir == "Read" {
				_, err = conn.Read(make([]byte, 8))
			} else {
				_, err = conn.Write([]byte("x"))
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s returned %v after Close, want net.ErrClosed", dir, err)
			}
		})
	}
}
