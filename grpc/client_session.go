//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package grpc

import (
	"context"
	"errors"
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

	stream     grpc.ServerStream // For server-side sessions
	frameID    uint64
	mu         sync.Mutex
	closed     int32
	remoteAddr net.Addr

	// streamCancel cancels the client stream's context (AER-010). Set on
	// dialed sessions; nil for server-side sessions. Invoked from Close so
	// the long-lived stream tears down deterministically.
	streamCancel context.CancelFunc
}

// runClientStream manages the client-side bidirectional stream.
func (s *GrpcSession) runClientStream(ctx context.Context) {
	// Own a cancellable child context so that when the send loop exits we can
	// abort the recv pump's blocking stream.Recv() and join it before closing
	// recvCh (AER-034).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create the bidi stream via the generated client
	client := pb.NewTransportServiceClient(s.conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		close(s.recvCh) // no pump started — safe to close directly
		return
	}

	// Recv pump: stream → recvCh. AER-034: recvCh is closed by THIS goroutine
	// only after the pump has exited (recvDone), so the pump can never send on
	// a closed channel — the previous `defer close(s.recvCh)` raced the pump's
	// send and could panic the process on shutdown.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case s.recvCh <- frame.Data:
			case <-s.closeCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Send pump: sendCh → stream
sendLoop:
	for {
		select {
		case <-ctx.Done():
			stream.CloseSend()
			break sendLoop
		case <-s.closeCh:
			stream.CloseSend()
			break sendLoop
		case data, ok := <-s.sendCh:
			if !ok {
				stream.CloseSend()
				break sendLoop
			}
			if err := stream.Send(&pb.Frame{Data: data, Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
				break sendLoop
			}
		}
	}

	cancel()   // abort a recv pump blocked in stream.Recv()
	<-recvDone // join it
	close(s.recvCh)
}

// Send sends data through the gRPC stream.
func (s *GrpcSession) Send(ctx context.Context, payload []byte) error {
	if atomic.LoadInt32(&s.closed) == 1 {
		return errors.New("session closed")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closeCh:
		return errors.New("session closed")
	case s.sendCh <- payload:
		return nil
	}
}

// Receive receives data from the gRPC stream.
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
	// AER-010: tear down the long-lived client stream deterministically.
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
