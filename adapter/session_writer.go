/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// sessionWriteRetryWindow bounds how long sessionWriter retries one Write through
// temporary errors. A conn past it is treated as failed: a sender waiting behind a
// transport that stays this busy learns it from the session's end.
const sessionWriteRetryWindow = 5 * time.Second

// errSessionWriterFailed is what a Write answers once an earlier one has given up on
// the conn (failed): the framing may be cut there, so no later frame is written.
var errSessionWriterFailed = errors.New("aether adapter: the session's writer has failed")

// longAgo is a write deadline already passed, which makes a conn's blocked Write
// return at once.
var longAgo = time.Unix(1, 0)

// sessionWriter is a TCPSession's path to its conn. Its transport carries the
// session's frames in one sequence with no retransmit, so a frame cannot be written
// again from its start once part of it has gone: a temporary error (EAGAIN, an i/o
// timeout) retries from the byte the conn stopped at, within sessionWriteRetryWindow,
// which is what keeps the framing whole and the frame from being lost. Any other error,
// or the window's end, is sticky (failed), and writeFrame and the writeLoop end the
// session on it (TCPSession.failWrite). Every caller holds the session's write turn.
//
// Two write deadlines bound a write the conn does not take. A frame written under a
// caller's context (beginFrame) gives up at that context's end while none of its bytes
// has gone, which leaves the writer and the framing whole; this is how a Ping
// (aether.RunKeepalive's probe) or an OpenStream returns under its context on a conn
// that takes nothing. A write that starts once the session has closed waits
// at most closeBound, the keepalive plan's probe wait, and fails past it, so the RESETs
// CloseWithError writes before its conn.Close cannot hold the close on such a conn. A
// frame from the writeLoop has neither: how long a live peer may take nothing is the
// keepalive's to decide (aether.RunKeepalive), and its Ping fails under its context.
type sessionWriter struct {
	conn       net.Conn
	closed     <-chan struct{}
	closeBound func() time.Duration
	fail       atomic.Bool

	// frameCtx is the context of the frame being written and frameSent the bytes of it
	// already on the conn (beginFrame, endFrame); the write turn guards both.
	frameCtx  context.Context
	frameSent int
}

func newSessionWriter(conn net.Conn, closed <-chan struct{}, closeBound func() time.Duration) *sessionWriter {
	return &sessionWriter{conn: conn, closed: closed, closeBound: closeBound}
}

// failed reports whether a Write has given up on the conn.
func (w *sessionWriter) failed() bool { return w.fail.Load() }

// beginFrame starts a frame written under ctx: until its first byte reaches the conn,
// a Write gives up at ctx's end with ctx's error. endFrame ends it. A frame begun with
// no call (the writeLoop's) has no context.
func (w *sessionWriter) beginFrame(ctx context.Context) {
	w.frameCtx, w.frameSent = ctx, 0
}

// endFrame ends the frame beginFrame started.
func (w *sessionWriter) endFrame() {
	w.frameCtx, w.frameSent = nil, 0
}

func (w *sessionWriter) Write(p []byte) (int, error) {
	if w.fail.Load() {
		return 0, errSessionWriterFailed
	}
	var (
		total   int
		giveUp  time.Time
		backoff = time.Millisecond
	)
	for {
		n, byContext, closing, err := w.writeOnce(p[total:])
		total += n
		w.frameSent += n
		if err == nil {
			if total == len(p) {
				return total, nil
			}
			w.fail.Store(true)
			return total, io.ErrShortWrite
		}
		if byContext {
			if w.frameSent == 0 {
				return total, w.frameCtx.Err()
			}
			// Part of the frame is on the conn: it is written whole, whatever its
			// context, or the framing is cut.
			w.frameCtx = nil
			continue
		}
		if closing || !isTemporaryNetError(err) {
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

// writeOnce is one conn.Write under the writer's deadlines: the frame's context while
// none of the frame has gone, which a watcher turns into a passed write deadline when
// the context ends (byContext reports that it did), and closeBound from now on a
// closed session (closing). It clears what deadline it set before it returns.
func (w *sessionWriter) writeOnce(p []byte) (n int, byContext, closing bool, err error) {
	select {
	case <-w.closed:
		closing = true
	default:
	}
	var (
		mu       sync.Mutex
		fired    bool
		finished bool
		stop     func() bool
	)
	if ctx := w.frameCtx; ctx != nil && ctx.Done() != nil && w.frameSent == 0 {
		stop = context.AfterFunc(ctx, func() {
			mu.Lock()
			defer mu.Unlock()
			if !finished {
				fired = true
				_ = w.conn.SetWriteDeadline(longAgo)
			}
		})
	}
	if closing && w.closeBound != nil {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.closeBound()))
	}
	n, err = w.conn.Write(p)
	if stop != nil {
		stop()
	}
	mu.Lock()
	finished = true
	byContext = fired && err != nil
	reset := fired || closing
	mu.Unlock()
	if reset {
		_ = w.conn.SetWriteDeadline(time.Time{})
	}
	return n, byContext, closing, err
}

// isTemporaryNetError returns true when err carries a Temporary() that reports true
// (kernel-level transient like EAGAIN or i/o timeout).
func isTemporaryNetError(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}
