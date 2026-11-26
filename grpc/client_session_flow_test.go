//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// scriptedTransport is a TransportService whose Stream runs the function a
// test gives it, so a test decides exactly what the server sends and how it
// ends the stream.
type scriptedTransport struct {
	pb.UnimplementedTransportServiceServer
	stream func(pb.TransportService_StreamServer) error
}

func (s *scriptedTransport) Stream(st pb.TransportService_StreamServer) error { return s.stream(st) }

// scriptedServer serves stream over an in-memory listener and returns a
// client connection to it.
func scriptedServer(t *testing.T, stream func(pb.TransportService_StreamServer) error) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterTransportServiceServer(gs, &scriptedTransport{stream: stream})
	go func() { _ = gs.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		// A test that ends the connection itself has closed cc already, and a
		// second Close answers codes.Canceled.
		if err := cc.Close(); err != nil && status.Code(err) != codes.Canceled {
			t.Errorf("cc.Close: %v", err)
		}
		gs.Stop()
		if err := lis.Close(); err != nil {
			t.Errorf("lis.Close: %v", err)
		}
	})
	return cc
}

// clientSession starts a GrpcSession's client stream over cc as
// GrpcTransport.Dial builds one. It leaves conn unset so that closing the
// session does not close a connection the test shares between rounds.
func clientSession(t *testing.T, cc *grpc.ClientConn) *GrpcSession {
	t.Helper()
	streamCtx, streamCancel := context.WithCancel(context.Background())
	s := newClientSession(streamCancel)
	go s.runClientStreamOver(streamCtx, cc)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// receiveAll returns how many frames Receive handed over before it reported an
// end, and that end.
func receiveAll(s *GrpcSession) (frames int, end error) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), bridgeHangBound)
		_, err := s.Receive(ctx)
		cancel()
		if err != nil {
			return frames, err
		}
		frames++
	}
}

// Receive hands over every frame the server sent and then the way the server
// ended the stream, whether or not the application sends in the meantime. The
// server here sends more frames than the session buffers and ends the stream;
// the reader has not started, so the receive pump is waiting on a full buffer;
// the application sends twice into a stream that has ended; then the reader
// drains. A send that fails must not end the receive side: the frames still
// queued and the server's status are what tell a cut stream from a finished
// one.
func TestGrpcSession_ReceiveHandsOverEveryFrameThenTheServersEnd(t *testing.T) {
	const frames = 200
	for name, end := range map[string]error{"the server cut the stream": status.Error(codes.Aborted, "cut"), "the server finished": nil} {
		t.Run(name, func(t *testing.T) {
			cc := scriptedServer(t, func(st pb.TransportService_StreamServer) error {
				for i := 0; i < frames; i++ {
					if err := st.Send(&pb.Frame{Data: []byte{byte(i)}}); err != nil {
						return err
					}
				}
				return end
			})
			for round := 0; round < 5; round++ {
				s := clientSession(t, cc)
				time.Sleep(150 * time.Millisecond) // the server has ended; the pump waits on a full buffer
				for k := 0; k < 2; k++ {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					_ = s.Send(ctx, []byte("reply"))
					cancel()
					time.Sleep(20 * time.Millisecond)
				}
				got, gotEnd := receiveAll(s)
				if got != frames {
					t.Fatalf("round %d: Receive handed over %d of %d frames, then %v", round, got, frames, gotEnd)
				}
				if end == nil && !errors.Is(gotEnd, io.EOF) {
					t.Fatalf("round %d: a finished stream ended with %v, want io.EOF", round, gotEnd)
				}
				if end != nil && status.Code(gotEnd) != codes.Aborted {
					t.Fatalf("round %d: a stream the server cut with Aborted ended with %v", round, gotEnd)
				}
				_ = s.Close()
			}
		})
	}
}

// Once the server has ended the stream, Send is refused: nothing sent from
// here can arrive. Accepting the payload would return nil for bytes no one
// will send, and once the session's send buffer filled the next Send would
// wait for the caller's own deadline, or forever without one.
func TestGrpcSession_SendIsRefusedOnceTheStreamHasEnded(t *testing.T) {
	cc := scriptedServer(t, func(st pb.TransportService_StreamServer) error {
		return status.Error(codes.Aborted, "cut")
	})
	s := clientSession(t, cc)
	if _, end := receiveAll(s); status.Code(end) != codes.Aborted {
		t.Fatalf("Receive ended with %v, want the server's Aborted", end)
	}
	for i := 0; i < 80; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := s.Send(ctx, []byte("late"))
		cancel()
		if err == nil {
			t.Fatalf("Send %d after the stream ended returned nil", i)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Send %d after the stream ended waited for its own deadline: %v", i, err)
		}
	}
}

// A session whose stream cannot open reports why. Receive returns that error,
// not io.EOF: a dial that never reached the server is not a stream the server
// finished.
func TestGrpcSession_AStreamThatCannotOpenReportsWhy(t *testing.T) {
	cc := scriptedServer(t, func(pb.TransportService_StreamServer) error { return nil })
	if err := cc.Close(); err != nil {
		t.Fatalf("cc.Close: %v", err)
	}
	s := clientSession(t, cc)
	_, end := receiveAll(s)
	if end == nil || errors.Is(end, io.EOF) {
		t.Fatalf("Receive on a session whose stream could not open = %v, want the reason it could not", end)
	}
}

// Close cuts the stream, and the server reads it as cut. Send returns once a
// payload is queued, so payloads queued at Close are dropped; ending the
// stream with a half-close would then tell the server a stream with frames
// missing was a finished one. Each round waits for the server to hold the
// stream before it sends and closes, since a session closed before its stream
// opens reaches no server at all.
func TestGrpcSession_CloseEndsTheStreamAsCutNotFinished(t *testing.T) {
	const rounds = 40
	var finished atomic.Int32
	opened := make(chan struct{}, rounds)
	ends := make(chan struct{}, rounds)
	cc := scriptedServer(t, func(st pb.TransportService_StreamServer) error {
		opened <- struct{}{}
		defer func() { ends <- struct{}{} }()
		for {
			if _, err := st.Recv(); err != nil {
				if errors.Is(err, io.EOF) {
					finished.Add(1)
				}
				return nil
			}
		}
	})
	for round := 0; round < rounds; round++ {
		// The session is given a cancel that does nothing, so the stream ends
		// only by what the session's own loop does when it sees the close. With
		// Dial's cancel, Close cancels the stream itself and that would reach
		// the server ahead of, or behind, whatever the loop did.
		s := newClientSession(func() {})
		go s.runClientStreamOver(context.Background(), cc)
		t.Cleanup(func() { _ = s.Close() })
		select {
		case <-opened:
		case <-time.After(bridgeHangBound):
			t.Fatalf("round %d: the server did not receive the stream within %v", round, bridgeHangBound)
		}
		for i := 0; i < 8; i++ {
			if err := s.Send(context.Background(), []byte{byte(i)}); err != nil {
				t.Fatalf("round %d: Send: %v", round, err)
			}
		}
		_ = s.Close()
		select {
		case <-ends:
		case <-time.After(bridgeHangBound):
			t.Fatalf("round %d: the server's stream had not ended %v after Close", round, bridgeHangBound)
		}
	}
	if n := finished.Load(); n != 0 {
		t.Fatalf("in %d of %d rounds the server read a closed session's stream as finished", n, rounds)
	}
}
