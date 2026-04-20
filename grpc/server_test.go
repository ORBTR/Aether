//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
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
	msg := []byte("grpc-dial:" + string(localNode) + ":" + string(remoteNode))
	sig := ed25519.Sign(priv, msg)
	md := metadata.Pairs(
		MetadataNodeID, string(localNode),
		MetadataSignature, hex.EncodeToString(sig),
		MetadataPubKey, hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	)
	return metadata.NewOutgoingContext(ctx, md)
}

// newBufconnServer starts an in-memory gRPC server bound to the given
// transport and returns a dial-able client connection.
func newBufconnServer(t *testing.T, srv *GrpcTransport) (*grpc.ClientConn, func()) {
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
	cc, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
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
	gt := NewGrpcTransport(GrpcTransportConfig{
		LocalNode:  nodeID,
		PrivateKey: priv,
		ListenAddr: "",
	})
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
