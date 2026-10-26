//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package grpc

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// closeFlushBound is how long transportServer.Stream lets the send pump
// forward what the session wrote before its Close. A pump still held by the
// peer's flow control after it is cut off, and the RPC ends with
// codes.Aborted, so the peer reads a stream that was cut short rather than a
// clean end. It bounds the session's Close, which waits for both pumps.
const closeFlushBound = 2 * time.Second

// Stream handles a bidirectional streaming connection.
// Each Stream RPC becomes one mesh session (like one WebSocket connection),
// read and written through the grpcPipeConn the two net.Pipes below make.
// The RPC lasts until its stream ends or the session closes; see the end
// of the function.
func (s *transportServer) Stream(stream pb.TransportService_StreamServer) error {
	nodeID, err := s.transport.extractNodeIDVerified(stream.Context())
	if err != nil {
		return err
	}

	// One net.Pipe per direction bridges the gRPC stream to the net.Conn
	// the session reads and writes, so each direction has net.Pipe's real
	// deadlines and closes on its own. The receive pump writes inPump and
	// the session reads in; the session writes out and the send pump
	// reads outPump. endBridgeRecv closes the pump ends when the receive
	// pump stops, and says which, and records a lost stream's error for
	// conn's Read.
	in, inPump := net.Pipe()
	out, outPump := net.Pipe()
	conn := newGrpcPipeConn(in, out)
	conn.recvDone, conn.sendDone = make(chan struct{}), make(chan struct{})

	// Pump: gRPC stream recv → inPump (so the session's reads see it)
	go func() {
		defer close(conn.recvDone)
		var recvErr error
		defer func() { endBridgeRecv(recvErr, conn, inPump, outPump) }()
		for {
			frame, err := stream.Recv()
			if err != nil {
				recvErr = err
				return
			}
			if _, err := inPump.Write(frame.Data); err != nil {
				recvErr = err
				return
			}
		}
	}()

	// Pump: outPump → gRPC stream send (so the session's writes reach remote)
	go func() {
		defer close(conn.sendDone)
		defer outPump.Close()
		buf := make([]byte, 65536)
		for {
			n, err := outPump.Read(buf)
			if err != nil {
				return
			}
			if err := stream.Send(&pb.Frame{Data: buf[:n], Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
				return
			}
		}
	}()

	session := aether.NewConnection(s.transport.localNode, nodeID, conn, aether.ProtoGRPC)
	session.OnClose(func() { conn.Close() })

	select {
	case s.transport.incoming <- aether.IncomingSession{Session: session}:
	default:
		// end, not Close: Close waits for the receive pump, which waits
		// for this function to return.
		conn.end()
		return errors.New("grpc: incoming session buffer full")
	}

	// Returning is what ends the RPC: gRPC then sends the status, which
	// the peer's Recv reads as the end, and cancels the stream, which
	// returns a pump blocked in Recv or Send. So the RPC is held open
	// until the stream ends or the session's Close. A stream that ended
	// first ends the session's write half here as well, because after the
	// peer's CloseSend the receive pump has already returned without
	// closing outPump, and the send pump would otherwise wait in its Read
	// for a Write it cannot deliver.
	select {
	case <-stream.Context().Done():
		_ = outPump.Close()
		return nil
	case <-conn.ended:
	}

	// The session closed. net.Pipe hands a Write's bytes to the send pump
	// before stream.Send runs, so a Write that returned nil may still be in
	// the pump; ending the RPC now would send the status ahead of them and
	// the peer would read a clean end with them missing. Close has closed
	// the session's write end, so the pump sends what it holds and then
	// returns; the RPC ends after that. A pump the peer's flow control still
	// holds after closeFlushBound is cut off with codes.Aborted.
	select {
	case <-conn.sendDone:
		return nil
	case <-stream.Context().Done():
		return nil
	case <-time.After(closeFlushBound):
		return status.Error(codes.Aborted, "grpc: the session closed before its last writes could be sent")
	}
}

// endBridgeRecv closes the pump ends of transportServer.Stream's two pipes
// when its receive pump stops with recvErr. io.EOF is the peer's
// CloseSend: only inPump closes, so the session reads io.EOF and can still
// write the response the peer is draining. Any other error means the
// stream is lost: conn records recvErr for its Read, and both ends close,
// outPump first. grpcPipeConn.Read reports the end only once inPump is
// closed, so a session that writes after reading the end finds its Write
// already failing and hands no bytes to a send pump that cannot deliver
// them, and the error is recorded before inPump closes, so that Read
// always finds it.
func endBridgeRecv(recvErr error, conn *grpcPipeConn, inPump, outPump io.Closer) {
	if !errors.Is(recvErr, io.EOF) {
		conn.lost.Store(&lostStream{recvErr})
		_ = outPump.Close()
	}
	_ = inPump.Close()
}

// lostStream is the receive pump's error for a stream that ended other
// than by the peer's CloseSend.
type lostStream struct{ err error }

// grpcPipeConn is the session's side of the two net.Pipes
// transportServer.Stream bridges to one gRPC stream; aether.NewConnection
// reads and writes it. Read takes the inbound pipe and Write the outbound
// one, so each direction ends on its own: Read returns io.EOF after the
// peer's CloseSend while Write still reaches the peer. A lost stream is
// not a half-close: Read returns the receive pump's own error for it,
// and io.EOF only for the CloseSend, so a session that only reads can
// tell a truncated inbound stream from a finished one. Its deadlines are
// the pipes': a Read or Write blocked past its deadline returns
// os.ErrDeadlineExceeded, and a later deadline makes it usable again.
// Close closes both directions.
//
// A direction the pumps have ended is not a closed conn, and its deadline
// setter still succeeds. net.Pipe refuses a deadline once either of its
// ends is closed, and endBridgeRecv closes inPump on the peer's CloseSend
// while the write half is live; passing that refusal on would make a
// session that sets a read deadline before each Read see the refusal or
// io.EOF depending on which call the pump's close raced. An ended
// direction has no Read or Write left to bound, since each returns the
// end at once, so pumpEnded reports success and the Read or Write reports
// the end. Only Close makes a setter fail.
type grpcPipeConn struct {
	in     net.Conn                   // the session reads the peer's frames here
	out    net.Conn                   // the session's writes go to the send pump here
	closed atomic.Bool                // set by Close; see pumpEnded
	lost   atomic.Pointer[lostStream] // set by endBridgeRecv; see Read

	closeOnce sync.Once
	closeErr  error         // what the first Close returns
	ended     chan struct{} // closed by Close; transportServer.Stream returns on it
	// recvDone and sendDone are closed by the receive and the send pump
	// as they return; Close waits for both. nil on a conn with no pumps.
	recvDone, sendDone chan struct{}
}

func newGrpcPipeConn(in, out net.Conn) *grpcPipeConn {
	return &grpcPipeConn{in: in, out: out, ended: make(chan struct{})}
}

// Read reads the inbound pipe. The pipe reports any close of its far end
// as io.EOF; when endBridgeRecv closed it for a lost stream, Read returns
// the error the receive pump recorded instead.
func (c *grpcPipeConn) Read(b []byte) (int, error) {
	n, err := c.in.Read(b)
	if err == io.EOF {
		if lost := c.lost.Load(); lost != nil {
			return n, lost.err
		}
	}
	return n, err
}

func (c *grpcPipeConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *grpcPipeConn) LocalAddr() net.Addr         { return grpcNetAddr{} }
func (c *grpcPipeConn) RemoteAddr() net.Addr        { return grpcNetAddr{} }

// Close closes the session's ends of both pipes, which returns its
// blocked Read and Write, ends the RPC, and waits for both pumps to
// return. It runs once; a later Close returns nil at once.
// transportServer.Stream ends the RPC only once the send pump has sent what
// it already holds, so every Write that returned nil reaches the peer ahead
// of the RPC's end; net.Pipe holds no bytes of its own, so the order the two
// ends close in decides nothing. A Send the peer's flow control
// still holds after closeFlushBound is cut off and the RPC ends with
// codes.Aborted, so Close returns within that bound and the peer never reads
// a stream with missing bytes as a clean end.
func (c *grpcPipeConn) Close() error {
	if !c.end() {
		return nil
	}
	for _, done := range []chan struct{}{c.recvDone, c.sendDone} {
		if done != nil {
			<-done
		}
	}
	return c.closeErr
}

// end is Close without the wait for the pumps, and reports whether this
// call did the closing. transportServer.Stream calls it on its own
// goroutine for a session it never hands over, where waiting for the
// receive pump would wait for Stream itself to return.
func (c *grpcPipeConn) end() bool {
	first := false
	c.closeOnce.Do(func() {
		first = true
		c.closed.Store(true)
		outErr := c.out.Close()
		inErr := c.in.Close()
		c.closeErr = errors.Join(inErr, outErr)
		close(c.ended)
	})
	return first
}

func (c *grpcPipeConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *grpcPipeConn) SetReadDeadline(t time.Time) error {
	return c.pumpEnded(c.in.SetReadDeadline(t))
}

func (c *grpcPipeConn) SetWriteDeadline(t time.Time) error {
	return c.pumpEnded(c.out.SetWriteDeadline(t))
}

// pumpEnded turns a pipe's refusal of a deadline into success unless
// Close caused it: before Close, the only closed pipe end is one
// endBridgeRecv or the send pump closed.
func (c *grpcPipeConn) pumpEnded(err error) error {
	if err != nil && !c.closed.Load() {
		return nil
	}
	return err
}

type grpcNetAddr struct{}

func (grpcNetAddr) Network() string { return "grpc" }
func (grpcNetAddr) String() string  { return "grpc" }
