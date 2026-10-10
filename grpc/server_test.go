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
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// makeAuthedContext constructs an outgoing context with the metadata the server
// interceptor expects: NodeID + hex(ed25519 signature) + hex(pubkey).
func makeAuthedContext(t *testing.T, ctx context.Context, priv ed25519.PrivateKey, localNode, remoteNode aether.NodeID) context.Context {
	t.Helper()
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	nonceStr := "test-nonce-" + tsStr
	msg := []byte("grpc-dial:" + string(localNode) + ":" + string(remoteNode) + ":" + tsStr + ":" + nonceStr)
	sig := ed25519.Sign(priv, msg)
	md := metadata.Pairs(
		MetadataNodeID, string(localNode),
		MetadataSignature, hex.EncodeToString(sig),
		MetadataPubKey, hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		MetadataNonce, nonceStr,
		MetadataTimestamp, tsStr,
	)
	return metadata.NewOutgoingContext(ctx, md)
}

// newBufconnServer starts an in-memory gRPC server bound to the given
// transport and returns a dial-able client connection; extra dial options
// are appended to the defaults.
func newBufconnServer(t *testing.T, srv *GrpcTransport, extra ...grpc.DialOption) (*grpc.ClientConn, func()) {
	t.Helper()
	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	gs := grpc.NewServer(
		grpc.UnaryInterceptor(srv.unaryAuthInterceptor),
		grpc.StreamInterceptor(srv.streamAuthInterceptor),
	)
	srv.server = gs
	RegisterTransportService(gs, srv)

	go func() {
		_ = gs.Serve(lis)
	}()

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	opts := append([]grpc.DialOption{
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}, extra...)
	cc, err := grpc.DialContext(context.Background(), "bufnet", opts...)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	return cc, func() {
		cc.Close()
		gs.Stop()
		lis.Close()
	}
}

// freshServerTransport creates a GrpcTransport with a random Ed25519 identity.
func freshServerTransport(t *testing.T) (*GrpcTransport, ed25519.PrivateKey, aether.NodeID) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	gt, err := NewGrpcTransport(GrpcTransportConfig{
		LocalNode:  nodeID,
		PrivateKey: priv,
		ListenAddr: "",
	})
	if err != nil {
		t.Fatalf("NewGrpcTransport: %v", err)
	}
	return gt, priv, nodeID
}

// TestGrpcServer_Ping starts a server, invokes Ping, and verifies the response
// echoes the client timestamp, advances the server timestamp, and carries the
// server's NodeID — mirroring the Noise-UDP adapter's Ping semantics.
func TestGrpcServer_Ping(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)

	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	// Client identity (needed for auth interceptor)
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = makeAuthedContext(t, ctx, clientPriv, clientNodeID, serverNodeID)

	client := pb.NewTransportServiceClient(cc)
	start := time.Now().UnixNano()
	resp, err := client.Ping(ctx, &pb.PingRequest{
		TimestampNs: start,
		NodeId:      string(clientNodeID),
	})
	if err != nil {
		t.Fatalf("Ping RPC: %v", err)
	}
	if resp.ClientTimestampNs != start {
		t.Errorf("ClientTimestampNs not echoed: got %d, want %d", resp.ClientTimestampNs, start)
	}
	if resp.ServerTimestampNs < start {
		t.Errorf("ServerTimestampNs must advance past client ts: server=%d client=%d", resp.ServerTimestampNs, start)
	}
	if resp.NodeId != string(serverNodeID) {
		t.Errorf("ServerNodeID mismatch: got %q, want %q", resp.NodeId, serverNodeID)
	}
}

// TestGrpcServer_StreamRoundTrip opens a bidi Stream, sends one frame from the
// client, and confirms the server-side transport.Incoming() surfaces a session
// receiving those bytes — verifying the pipe-bridge wiring to TCPSession.
func TestGrpcServer_StreamRoundTrip(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)

	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = makeAuthedContext(t, ctx, clientPriv, clientNodeID, serverNodeID)

	client := pb.NewTransportServiceClient(cc)
	stream, err := client.Stream(ctx)
	if err != nil {
		t.Fatalf("open Stream: %v", err)
	}

	payload := []byte("hello-aether")
	if err := stream.Send(&pb.Frame{Data: payload, Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	// Server should surface an incoming session.
	select {
	case inc, ok := <-serverT.Incoming():
		if !ok {
			t.Fatal("Incoming channel closed")
		}
		if inc.Session == nil {
			t.Fatal("nil session on incoming")
		}
		if inc.Session.RemoteNodeID() != clientNodeID {
			t.Errorf("RemoteNodeID: got %q, want %q", inc.Session.RemoteNodeID(), clientNodeID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no incoming session within 3s")
	}
}

// TestGrpcServer_UnauthedRejected proves the stream interceptor rejects calls
// with no NodeID metadata — wire-format integrity check for auth.
func TestGrpcServer_UnauthedRejected(t *testing.T) {
	serverT, _, _ := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client := pb.NewTransportServiceClient(cc)
	_, err := client.Ping(ctx, &pb.PingRequest{TimestampNs: time.Now().UnixNano()})
	if err == nil {
		t.Fatal("expected Ping without metadata to fail auth")
	}
}

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
// Write that is not refused succeeds instead of blocking.
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
		conn := &grpcPipeConn{in: in, out: out}
		pumped := make(chan struct{})
		go func() {
			defer close(pumped)
			_, _ = io.Copy(io.Discard, outPump)
		}()

		var writeErr error
		endBridgeRecv(tc.recvErr, closeThen{inPump, func() {
			_, writeErr = conn.Write([]byte("x"))
		}}, outPump)

		if tc.writeEnds && writeErr == nil {
			t.Errorf("%s: a Write at the instant the inbound direction ended succeeded", name)
		}
		if !tc.writeEnds && writeErr != nil {
			t.Errorf("%s: a Write at the instant the inbound direction ended: %v, want nil", name, writeErr)
		}
		if n, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("%s: Read after the receive pump stopped = (%d, %v), want io.EOF", name, n, err)
		}
		_ = conn.Close()
		_ = outPump.Close()
		<-pumped
	}
}

// A stream that ends other than by the peer's CloseSend ends both
// directions: once the peer cancels and the server session's Read has
// reported the end, its next Write fails instead of handing bytes to a
// send pump that cannot deliver them. The bridge is ended but not closed,
// so the deadline setters still succeed and the Write itself reports the
// end.
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
	if _, err := conn.Read(make([]byte, 8)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after the peer cancelled: err = %v, want the bridge's end", err)
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
