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
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"google.golang.org/grpc"
)

// dialClientSession starts a GrpcSession's client stream over cc from a fresh
// client key, as GrpcTransport.Dial does, and returns the session. The
// session's Close closes cc.
func dialClientSession(t *testing.T, cc *grpc.ClientConn, serverNodeID aether.NodeID) *GrpcSession {
	t.Helper()
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}
	streamCtx, streamCancel := context.WithCancel(makeAuthedContext(t, context.Background(), clientPriv, clientNodeID, serverNodeID))
	s := newClientSession(streamCancel)
	s.conn = cc
	s.localNode = clientNodeID
	s.remoteNode = serverNodeID
	go s.runClientStream(streamCtx)
	return s
}

// receiveWithin returns what s.Receive answers, failing the test when it has
// not answered within bridgeHangBound.
func receiveWithin(t *testing.T, s *GrpcSession, what string) ([]byte, error) {
	t.Helper()
	type answer struct {
		data []byte
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		data, err := s.Receive(context.Background())
		got <- answer{data, err}
	}()
	select {
	case a := <-got:
		return a.data, a.err
	case <-time.After(bridgeHangBound):
		t.Fatalf("%s: Receive was still blocked after %v", what, bridgeHangBound)
		return nil, nil
	}
}

// A dialed session's Receive ends with io.EOF once the server has ended the
// RPC, with the session not closed and nothing left to send. The server
// closing its side is how a peer's GoAway or a closed listener reaches a
// dialer, and a Receive that stayed blocked would hold the reader of every
// such session until its own deadline.
func TestGrpcSession_ReceiveEndsWhenTheServerEndsTheRPC(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	s := dialClientSession(t, cc, serverNodeID)
	defer s.Close()
	if err := s.Send(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var serverSession aether.Connection
	select {
	case inc := <-serverT.Incoming():
		serverSession = inc.Session
	case <-time.After(3 * time.Second):
		t.Fatal("no incoming session within 3s")
	}
	if err := serverSession.Send(context.Background(), []byte("last")); err != nil {
		t.Fatalf("server Send: %v", err)
	}
	if err := serverSession.Close(); err != nil {
		t.Fatalf("server Close: %v", err)
	}

	// What the server sent before it closed arrives first, then the end.
	data, err := receiveWithin(t, s, "the frame sent before the close")
	if err != nil || string(data) != "last" {
		t.Fatalf("Receive = (%q, %v), want the frame the server sent before it closed", data, err)
	}
	if _, err := receiveWithin(t, s, "after the server ended the RPC"); !errors.Is(err, io.EOF) {
		t.Fatalf("Receive after the server ended the RPC = %v, want io.EOF", err)
	}
}

// A stream the server ends with an error is not read as a finished one:
// Receive returns that error, never io.EOF, so a dialer that was refused or
// cut does not take what it received for a whole stream.
func TestGrpcSession_ReceiveReportsAStreamTheServerEndedWithAnError(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	// A full incoming buffer makes the server refuse the next stream.
	for i := 0; i < cap(serverT.incoming); i++ {
		serverT.incoming <- aether.IncomingSession{}
	}
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	s := dialClientSession(t, cc, serverNodeID)
	defer s.Close()

	_, err := receiveWithin(t, s, "after the server refused the stream")
	if err == nil {
		t.Fatal("Receive returned no error for a stream the server refused")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("Receive = %v for a stream the server refused: a refused stream reads as a finished one", err)
	}
}
