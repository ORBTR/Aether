//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The connection transportServer.Stream hands the session has real
// deadlines. A Read with nothing to read returns at its read deadline;
// with a client that never receives, a Write that the gRPC send window
// has stopped returns at its write deadline. Fixed 64 KiB windows keep
// the client from growing its window, so the stop comes after a few
// hundred KiB.
func TestGrpcServer_StreamBridgeDeadlines(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT,
		grpc.WithInitialWindowSize(1<<16),
		grpc.WithInitialConnWindowSize(1<<16),
	)
	defer cleanup()

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctx = makeAuthedContext(t, ctx, clientPriv, clientNodeID, serverNodeID)

	stream, err := pb.NewTransportServiceClient(cc).Stream(ctx)
	if err != nil {
		t.Fatalf("open Stream: %v", err)
	}
	if err := stream.Send(&pb.Frame{Data: []byte("hello"), Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	var conn net.Conn
	select {
	case inc := <-serverT.Incoming():
		p, ok := inc.Session.(interface{ NetConn() net.Conn })
		if !ok {
			t.Fatalf("incoming session %T exposes no NetConn", inc.Session)
		}
		conn = p.NetConn()
	case <-time.After(3 * time.Second):
		t.Fatal("no incoming session within 3s")
	}
	defer conn.Close()

	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first Read = (%q, %v), want hello", buf[:n], err)
	}
	readDeadline := time.Now().Add(100 * time.Millisecond)
	if err := conn.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read with nothing sent: err = %v, want os.ErrDeadlineExceeded", err)
	}
	if time.Now().Before(readDeadline) {
		t.Fatal("Read returned before its deadline")
	}

	writeDeadline := time.Now().Add(300 * time.Millisecond)
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	chunk := make([]byte, 32<<10)
	written := 0
	for {
		n, err := conn.Write(chunk)
		written += n
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write after %d bytes: err = %v, want os.ErrDeadlineExceeded", written, err)
			}
			break
		}
		if written > 64<<20 {
			t.Fatalf("%d bytes written to a client that never receives; no Write blocked", written)
		}
	}
	if time.Now().Before(writeDeadline) {
		t.Fatal("Write returned before its deadline")
	}
}

// openBridge opens one TransportService stream from a fresh client key,
// sends "hello", and returns the client stream with its cancel, plus the
// net.Conn of the server session the stream became, already past "hello".
func openBridge(t *testing.T, serverT *GrpcTransport, cc *grpc.ClientConn, serverNodeID aether.NodeID) (pb.TransportService_StreamClient, context.CancelFunc, net.Conn) {
	t.Helper()
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	ctx = makeAuthedContext(t, ctx, clientPriv, clientNodeID, serverNodeID)
	stream, err := pb.NewTransportServiceClient(cc).Stream(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open Stream: %v", err)
	}
	if err := stream.Send(&pb.Frame{Data: []byte("hello"), Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
		cancel()
		t.Fatalf("send frame: %v", err)
	}
	var conn net.Conn
	select {
	case inc := <-serverT.Incoming():
		p, ok := inc.Session.(interface{ NetConn() net.Conn })
		if !ok {
			cancel()
			t.Fatalf("incoming session %T exposes no NetConn", inc.Session)
		}
		conn = p.NetConn()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("no incoming session within 3s")
	}
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "hello" {
		cancel()
		t.Fatalf("first Read = (%q, %v), want hello", buf[:n], err)
	}
	return stream, cancel, conn
}

// bridgeHangBound is the read deadline the bridge tests set before they
// wait for the peer's CloseSend or cancel to reach the server session. A
// passing run never waits for it: the event crosses an in-memory
// connection in well under a millisecond. It only turns a bridge that
// never reports the event into a failure, so it sits far above what a
// loaded machine running the race detector needs.
const bridgeHangBound = 10 * time.Second

// deadlineSetters returns conn's three deadline setters by name.
func deadlineSetters(conn net.Conn) map[string]func(time.Time) error {
	return map[string]func(time.Time) error{
		"SetDeadline":      conn.SetDeadline,
		"SetReadDeadline":  conn.SetReadDeadline,
		"SetWriteDeadline": conn.SetWriteDeadline,
	}
}

// The peer's CloseSend half-closes the bridge: the server session reads
// io.EOF and can still write the response the peer is draining, which
// the peer receives. The half-closed bridge is not a closed one, so every
// deadline setter still succeeds, a second Read reports io.EOF again, and
// only the session's own Close makes the setters fail.
func TestGrpcServer_StreamBridgeHalfClose(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()
	defer conn.Close()

	// Set before CloseSend, while both halves are open, so the Read below
	// is bounded whichever way the half-close races this call.
	if err := conn.SetReadDeadline(time.Now().Add(bridgeHangBound)); err != nil {
		t.Fatalf("SetReadDeadline on the open bridge: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if n, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after the peer's CloseSend = (%d, %v), want io.EOF", n, err)
	}

	// Read has reported the half-close, so the inbound pipe is closed for
	// certain from here on.
	later := time.Now().Add(bridgeHangBound)
	for name, set := range deadlineSetters(conn) {
		if err := set(later); err != nil {
			t.Errorf("%s on the half-closed bridge: %v, want nil while its write half is live", name, err)
		}
	}
	if n, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Errorf("second Read on the half-closed bridge = (%d, %v), want io.EOF", n, err)
	}
	if _, err := conn.Write([]byte("resp")); err != nil {
		t.Fatalf("server Write after the peer's CloseSend: %v", err)
	}
	f, err := stream.Recv()
	if err != nil || string(f.GetData()) != "resp" {
		t.Fatalf("peer Recv after its CloseSend = (%q, %v), want resp", f.GetData(), err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for name, set := range deadlineSetters(conn) {
		if err := set(later); err == nil {
			t.Errorf("%s after Close returned nil, want the closed bridge's refusal", name)
		}
	}
}

// On a bridge the peer has half-closed, SetDeadline still arms the live
// write half: with a peer that receives nothing, a Write that the gRPC
// send window has stopped returns at that deadline. Fixed 64 KiB windows
// stop the Write after a few hundred KiB. The test asserts no upper bound
// on how soon after the deadline the Write returns; the deadline is 300ms
// out only so that the loop usually reaches the stopped window first, and
// a Write that meets the deadline earlier returns the same error.
func TestGrpcServer_StreamBridgeWriteDeadlineAfterHalfClose(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT,
		grpc.WithInitialWindowSize(1<<16),
		grpc.WithInitialConnWindowSize(1<<16),
	)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(bridgeHangBound)); err != nil {
		t.Fatalf("SetReadDeadline on the open bridge: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if n, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after the peer's CloseSend = (%d, %v), want io.EOF", n, err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline on the half-closed bridge: %v", err)
	}
	chunk := make([]byte, 32<<10)
	written := 0
	for {
		n, err := conn.Write(chunk)
		written += n
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write after %d bytes: err = %v, want os.ErrDeadlineExceeded", written, err)
			}
			break
		}
		if written > 64<<20 {
			t.Fatalf("%d bytes written to a peer that never receives; no Write blocked", written)
		}
	}
	if time.Now().Before(deadline) {
		t.Fatal("Write returned before the deadline SetDeadline set")
	}
}

// closeThen is an io.Closer that runs then once the Closer it wraps has
// closed, so a test can act at the instant a pipe end closes.
type closeThen struct {
	io.Closer
	then func()
}

func (c closeThen) Close() error {
	err := c.Closer.Close()
	c.then()
	return err
}

// endBridgeRecv ends the outbound direction before the inbound one when
// the stream is gone: at the instant the inbound pipe closes, which is the
// first instant the session's Read can report the end, the session's Write
// already fails. On the peer's CloseSend it ends the inbound direction
// only, and the session's Write still reaches the send pump. A goroutine
// stands in for the send pump and takes whatever the session writes, so a
// Write that is not refused succeeds instead of blocking. The session's
// Read names the end from that same instant on: io.EOF for the peer's
// CloseSend, and the receive pump's own error, never io.EOF, for a lost
// stream.
func TestEndBridgeRecv_OutboundEndsBeforeInbound(t *testing.T) {
	for name, tc := range map[string]struct {
		recvErr   error
		writeEnds bool
	}{
		"stream error":           {errors.New("rpc error: code = Canceled"), true},
		"pipe closed under pump": {io.ErrClosedPipe, true},
		"peer CloseSend":         {io.EOF, false},
	} {
		in, inPump := net.Pipe()
		out, outPump := net.Pipe()
		conn := newGrpcPipeConn(in, out)
		pumped := make(chan struct{})
		go func() {
			defer close(pumped)
			_, _ = io.Copy(io.Discard, outPump)
		}()

		var writeErr error
		var reads []error
		endBridgeRecv(tc.recvErr, conn, closeThen{inPump, func() {
			_, writeErr = conn.Write([]byte("x"))
			_, err := conn.Read(make([]byte, 1))
			reads = append(reads, err)
		}}, outPump)

		if tc.writeEnds && writeErr == nil {
			t.Errorf("%s: a Write at the instant the inbound direction ended succeeded", name)
		}
		if !tc.writeEnds && writeErr != nil {
			t.Errorf("%s: a Write at the instant the inbound direction ended: %v, want nil", name, writeErr)
		}
		for i := 0; i < 2; i++ {
			_, err := conn.Read(make([]byte, 1))
			reads = append(reads, err)
		}
		for i, err := range reads {
			if tc.writeEnds && (!errors.Is(err, tc.recvErr) || errors.Is(err, io.EOF)) {
				t.Errorf("%s: Read %d from the instant the inbound direction ended = %v, want the pump's error %q and not io.EOF", name, i, err, tc.recvErr)
			}
			if !tc.writeEnds && !errors.Is(err, io.EOF) {
				t.Errorf("%s: Read %d from the instant the inbound direction ended = %v, want io.EOF", name, i, err)
			}
		}
		_ = conn.Close()
		_ = outPump.Close()
		<-pumped
	}
}

// A stream that ends other than by the peer's CloseSend ends both
// directions: once the peer cancels and the server session's Read has
// reported the end, its next Write fails instead of handing bytes to a
// send pump that cannot deliver them. The Read reports the cancel as the
// receive pump got it from gRPC, a Canceled status, and not as io.EOF,
// which would read as the peer's CloseSend. The bridge is ended but not
// closed, so the deadline setters still succeed and the Write itself
// reports the end.
func TestGrpcServer_StreamBridgeEndsBothDirectionsOnStreamError(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	_, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer conn.Close()

	// Set before the cancel, while both halves are open, so the Read below
	// is bounded whichever way the stream's end races this call.
	if err := conn.SetReadDeadline(time.Now().Add(bridgeHangBound)); err != nil {
		t.Fatalf("SetReadDeadline on the open bridge: %v", err)
	}
	cancel()
	if _, err := conn.Read(make([]byte, 8)); status.Code(err) != codes.Canceled || errors.Is(err, io.EOF) {
		t.Fatalf("Read after the peer cancelled: err = %v, want the stream's Canceled status and not io.EOF", err)
	}
	if _, err := conn.Write([]byte("lost")); err == nil {
		t.Fatal("server Write after the peer cancelled succeeded")
	}
	for name, set := range deadlineSetters(conn) {
		if err := set(time.Now().Add(bridgeHangBound)); err != nil {
			t.Errorf("%s on the ended bridge: %v, want nil before Close", name, err)
		}
	}
	if _, err := conn.Write([]byte("lost")); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server Write on the ended bridge: err = %v, want the bridge's end", err)
	}
}
