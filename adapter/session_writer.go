/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// sessionWriteRetryWindow bounds how long sessionWriter retries one Write through
// temporary errors. A conn past it is treated as failed: a sender waiting behind a
// transport that stays this busy learns it from the session's end.
const sessionWriteRetryWindow = 5 * time.Second

// sessionWriter is a TCPSession's path to its conn. Its transport carries the
// session's frames in one sequence with no retransmit, so a frame cannot be written
// again from its start once part of it has gone: a temporary error (EAGAIN, an i/o
// timeout) retries from the byte the conn stopped at, within sessionWriteRetryWindow,
// which is what keeps the framing whole and the frame from being lost. Any other error,
// or the window's end, is sticky (failed), and writeFrame and the writeLoop end the
// session on it (TCPSession.failWrite). Every caller holds the session's writeMu.
type sessionWriter struct {
	conn   net.Conn
	closed <-chan struct{}
	fail   atomic.Bool
}

func newSessionWriter(conn net.Conn, closed <-chan struct{}) *sessionWriter {
	return &sessionWriter{conn: conn, closed: closed}
}

// failed reports whether a Write has given up on the conn.
func (w *sessionWriter) failed() bool { return w.fail.Load() }

func (w *sessionWriter) Write(p []byte) (int, error) {
	var (
		total   int
		giveUp  time.Time
		backoff = time.Millisecond
	)
	for {
		n, err := w.conn.Write(p[total:])
		total += n
		if err == nil {
			if total == len(p) {
				return total, nil
			}
			w.fail.Store(true)
			return total, io.ErrShortWrite
		}
		if !isTemporaryNetError(err) {
			w.fail.Store(true)
			return total, err
		}
		now := time.Now()
		if giveUp.IsZero() {
			giveUp = now.Add(sessionWriteRetryWindow)
		} else if now.After(giveUp) {
			w.fail.Store(true)
			return total, err
		}
		select {
		case <-w.closed:
			w.fail.Store(true)
			return total, err
		case <-time.After(backoff):
		}
		if backoff < 50*time.Millisecond {
			backoff *= 2
		}
	}
}

// isTemporaryNetError returns true when err carries a Temporary() that reports true
// (kernel-level transient like EAGAIN or i/o timeout).
func isTemporaryNetError(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}
