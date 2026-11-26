//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
)

// GrpcSession implements aether.Connection for gRPC.
type GrpcSession struct {
	conn       *grpc.ClientConn
	localNode  aether.NodeID
	remoteNode aether.NodeID

	sendCh  chan []byte
	recvCh  chan []byte
	closeCh chan struct{}

	// sendDone is closed when the client stream stops taking payloads from
	// sendCh: the server ended the stream, a send on it failed, or the
	// session closed. Send reads it to refuse a payload nothing will send.
	sendDone chan struct{}

	stream     grpc.ServerStream // For server-side sessions
	frameID    uint64
	mu         sync.Mutex
	closed     int32
	remoteAddr net.Addr

	// streamCancel cancels the client stream's context. Set on
	// dialed sessions; nil for server-side sessions. Invoked from Close so
	// the long-lived stream tears down deterministically.
	streamCancel context.CancelFunc

	// recvErr is the error the client stream ended with when that was not
	// this session's own Close: the status the server ended it with, or why
	// it could not open. It is written by runClientStreamOver before recvCh
	// closes and read by Receive once recvCh is drained, and by Send once
	// sendDone is closed. It stays nil for a stream the server finished.
	recvErr atomic.Pointer[error]
}

// errStreamEnded is what Send returns once the client stream has stopped
// sending, joined with the error the stream ended with when there is one.
var errStreamEnded = errors.New("grpc session: the stream has ended")

// newClientSession returns a dialed session with its channels made and
// nothing running. GrpcTransport.Dial sets its connection and node ids and
// starts runClientStream.
func newClientSession(streamCancel context.CancelFunc) *GrpcSession {
	return &GrpcSession{
		sendCh:       make(chan []byte, 64),
		recvCh:       make(chan []byte, 64),
		closeCh:      make(chan struct{}),
		sendDone:     make(chan struct{}),
		streamCancel: streamCancel,
	}
}

// runClientStream manages the client-side bidirectional stream over the
// session's own connection.
func (s *GrpcSession) runClientStream(ctx context.Context) {
	s.runClientStreamOver(ctx, s.conn)
}

// runClientStreamOver opens the TransportService stream on conn and runs it
// until the server ends it or the session closes: a receive pump hands each
// frame to recvCh, and the send loop writes each payload from sendCh.
//
// The two directions end in one order, which Receive depends on. The receive
// pump returns only when the server has ended the stream, after handing over
// every frame it read, or when the session closes. The send loop never ends
// the pump: when the server ends the stream it stops, and when a send fails
// it stops sending and waits for the pump, because the frames the server
// sent before it ended and the status it ended with are still on their way to
// the reader, and they are what tell a cut stream from a finished one. recvCh
// is closed last, by this goroutine, once the pump has returned, so the pump
// never sends on a closed channel.
//
// A closing session cuts the stream by cancelling it and does not half-close
// it: Send returns once a payload is queued, so payloads still queued at
// Close are dropped, and a half-close would tell the server that a stream
// with frames missing had finished.
// TODO: send what sendCh holds and half-close before cancelling, under a
// bound as the server bridge's Close has, once a dialed session has a caller
// that needs its last payloads delivered.
func (s *GrpcSession) runClientStreamOver(ctx context.Context, conn *grpc.ClientConn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := pb.NewTransportServiceClient(conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		if atomic.LoadInt32(&s.closed) == 0 {
			s.recvErr.Store(&err)
		}
		close(s.sendDone)
		close(s.recvCh) // no pump started, so nothing else sends on it
		return
	}

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			frame, err := stream.Recv()
			if err != nil {
				// io.EOF is a stream the server finished. Any other error is
				// kept for Receive unless this session closed, in which case
				// it is the cancel Close sent.
				if !errors.Is(err, io.EOF) && atomic.LoadInt32(&s.closed) == 0 {
					s.recvErr.Store(&err)
				}
				return
			}
			select {
			case s.recvCh <- frame.Data:
			case <-s.closeCh:
				return
			}
		}
	}()

sendLoop:
	for {
		select {
		case <-recvDone:
			break sendLoop
		case <-s.closeCh:
			break sendLoop
		case data, ok := <-s.sendCh:
			if !ok {
				_ = stream.CloseSend()
				break sendLoop
			}
			if err := stream.Send(&pb.Frame{Data: data, Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
				break sendLoop
			}
		}
	}
	close(s.sendDone)

	// The pump finishes on its own unless the session closes first; only then
	// is the stream cancelled, to end a pump waiting in Recv.
	select {
	case <-recvDone:
	case <-s.closeCh:
	}
	cancel()
	<-recvDone
	close(s.recvCh)
}

// Send queues payload for the client stream and returns once it is queued,
// not once it is sent: a payload queued when the session closes or the stream
// ends is dropped. Once the stream has stopped sending, Send returns
// errStreamEnded, joined with the error the stream ended with when there is
// one, so a caller is not handed nil for bytes nothing will send.
func (s *GrpcSession) Send(ctx context.Context, payload []byte) error {
	if atomic.LoadInt32(&s.closed) == 1 {
		return aether.ErrSessionClosed
	}
	select {
	case <-s.sendDone:
		return s.streamEnded()
	default:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closeCh:
		return aether.ErrSessionClosed
	case <-s.sendDone:
		return s.streamEnded()
	case s.sendCh <- payload:
		return nil
	}
}

// streamEnded is the error Send returns once the stream has stopped sending.
func (s *GrpcSession) streamEnded() error {
	if err := s.recvErr.Load(); err != nil {
		return fmt.Errorf("%w: %w", errStreamEnded, *err)
	}
	return errStreamEnded
}

// Receive receives data from the gRPC stream. Once the server has ended the
// stream and everything it sent has been returned, Receive returns io.EOF for
// a stream the server finished and the server's error for one it refused or
// cut.
func (s *GrpcSession) Receive(ctx context.Context) ([]byte, error) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closeCh:
		return nil, io.EOF
	case data, ok := <-s.recvCh:
		if !ok {
			if err := s.recvErr.Load(); err != nil {
				return nil, *err
			}
			return nil, io.EOF
		}
		return data, nil
	}
}

// Close closes the session.
func (s *GrpcSession) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil // Already closed
	}

	close(s.closeCh)
	// Tear down the long-lived client stream deterministically.
	if s.streamCancel != nil {
		s.streamCancel()
	}

	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// RemoteAddr returns the remote address.
func (s *GrpcSession) RemoteAddr() net.Addr {
	if s.remoteAddr != nil {
		return s.remoteAddr
	}
	return &net.TCPAddr{}
}

// RemoteNodeID returns the remote node's ID.
func (s *GrpcSession) RemoteNodeID() aether.NodeID {
	return s.remoteNode
}

// Ping sends a ping and waits for pong, returning RTT.
func (s *GrpcSession) Ping(ctx context.Context, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Send ping frame
	if err := s.Send(pingCtx, []byte{0x02}); err != nil { // 0x02 = ping
		return 0, err
	}

	// Wait for pong
	data, err := s.Receive(pingCtx)
	if err != nil {
		return 0, err
	}

	if len(data) < 1 || data[0] != 0x03 { // 0x03 = pong
		return 0, errors.New("unexpected response to ping")
	}

	return time.Since(start), nil
}

func (s *GrpcSession) NetConn() net.Conn         { return nil } // gRPC doesn't expose raw net.Conn
func (s *GrpcSession) Protocol() aether.Protocol { return aether.ProtoGRPC }
func (s *GrpcSession) OnClose(fn func())         { /* gRPC handles lifecycle */ }
