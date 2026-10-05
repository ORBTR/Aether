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

// The peer's CloseSend half-closes the bridge: the server session reads
// io.EOF and can still write the response the peer is draining, which
// the peer receives.
func TestGrpcServer_StreamBridgeHalfClose(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()
	defer conn.Close()

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after the peer's CloseSend = (%d, %v), want io.EOF", n, err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("resp")); err != nil {
		t.Fatalf("server Write after the peer's CloseSend: %v", err)
	}
	f, err := stream.Recv()
	if err != nil || string(f.GetData()) != "resp" {
		t.Fatalf("peer Recv after its CloseSend = (%q, %v), want resp", f.GetData(), err)
	}
}

// A stream that ends other than by the peer's CloseSend ends both
// directions: once the peer cancels, the server session's next Write
// fails instead of handing bytes to a send pump that cannot deliver them.
func TestGrpcServer_StreamBridgeEndsBothDirectionsOnStreamError(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	_, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer conn.Close()

	cancel()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 8)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after the peer cancelled: err = %v, want the bridge's end", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) // may refuse: the write end is closed
	if _, err := conn.Write([]byte("lost")); err == nil {
		t.Fatal("server Write after the peer cancelled succeeded")
	}
}
