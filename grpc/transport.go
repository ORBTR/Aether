//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/ORBTR/aether/grpc/pb"
	"github.com/ORBTR/aether"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	// MetadataNodeID is the gRPC metadata key for NodeID
	MetadataNodeID = "x-hstles-nodeid"
	// MetadataSignature is the gRPC metadata key for signature
	MetadataSignature = "x-hstles-signature"
	// MetadataPubKey is the gRPC metadata key for hex-encoded Ed25519 public key
	MetadataPubKey = "x-hstles-pubkey"
)

// GrpcTransportConfig configures the gRPC aether.
// When TLSConfig is non-nil, it is used for both dial and listen. Otherwise
// the transport falls back to insecure credentials (for local/test use only —
// production deployments must supply TLSConfig).
type GrpcTransportConfig struct {
	LocalNode  aether.NodeID
	PrivateKey ed25519.PrivateKey
	ListenAddr string
	TLSConfig  *tls.Config
}

// GrpcTransport implements the Transport interface using gRPC.
type GrpcTransport struct {
	localNode  aether.NodeID
	privateKey ed25519.PrivateKey
	listenAddr string
	tlsConfig  *tls.Config
	server     *grpc.Server
	incoming   chan aether.IncomingSession
}

// NewGrpcTransport creates a new gRPC aether.
func NewGrpcTransport(cfg GrpcTransportConfig) *GrpcTransport {
	return &GrpcTransport{
		localNode:  cfg.LocalNode,
		privateKey: cfg.PrivateKey,
		listenAddr: cfg.ListenAddr,
		tlsConfig:  cfg.TLSConfig,
		incoming:   make(chan aether.IncomingSession, 32),
	}
}

// NewGrpcTransportFromConfig creates a gRPC transport from the unified Config.
// Returns nil if Config.GRPC is nil (protocol disabled).
func NewGrpcTransportFromConfig(cfg aether.Config) *GrpcTransport {
	if cfg.GRPC == nil {
		return nil
	}
	return NewGrpcTransport(GrpcTransportConfig{
		LocalNode:  cfg.NodeID,
		PrivateKey: cfg.PrivateKey,
		ListenAddr: cfg.GRPC.ListenAddr,
		TLSConfig:  cfg.GRPC.TLSConfig,
	})
}

// dialCredentials returns the appropriate client credentials.
func (t *GrpcTransport) dialCredentials() grpc.DialOption {
	if t.tlsConfig != nil {
		return grpc.WithTransportCredentials(credentials.NewTLS(t.tlsConfig))
	}
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// Dial establishes a gRPC connection to the provided target.
func (t *GrpcTransport) Dial(ctx context.Context, target aether.Target) (aether.Connection, error) {
	if target.Address == "" {
		return nil, errors.New("grpc: missing address")
	}

	// Create signed metadata to prove our identity
	message := []byte(fmt.Sprintf("grpc-dial:%s:%s", t.localNode, target.NodeID))
	signature := ed25519.Sign(t.privateKey, message)

	// Add metadata to outgoing context
	md := metadata.Pairs(
		MetadataNodeID, string(t.localNode),
		MetadataSignature, hex.EncodeToString(signature),
		MetadataPubKey, hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)),
	)
	dialCtx := metadata.NewOutgoingContext(ctx, md)

	conn, err := grpc.DialContext(dialCtx, target.Address,
		t.dialCredentials(),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoGRPC, target.NodeID, err)
	}

	// Create bidirectional stream session
	session := &GrpcSession{
		conn:       conn,
		localNode:  t.localNode,
		remoteNode: target.NodeID,
		sendCh:     make(chan []byte, 64),
		recvCh:     make(chan []byte, 64),
		closeCh:    make(chan struct{}),
	}

	// Start stream goroutine
	go session.runClientStream(ctx)

	return session, nil
}

// Listen starts accepting gRPC connections.
func (t *GrpcTransport) Listen(ctx context.Context) (aether.Listener, error) {
	addr := t.listenAddr
	if addr == "" {
		addr = ":0"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, aether.WrapOp("listen", aether.ProtoGRPC, "", err)
	}

	// Create gRPC server with transport service
	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(t.unaryAuthInterceptor),
		grpc.StreamInterceptor(t.streamAuthInterceptor),
	}
	if t.tlsConfig != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(t.tlsConfig)))
	}
	server := grpc.NewServer(serverOpts...)
	t.server = server

	// Register our transport service
	RegisterTransportService(server, t)

	go func() {
		if err := server.Serve(lis); err != nil {
			// Server stopped
		}
	}()

	return &GrpcListener{
		listener: lis,
		server:   server,
		incoming: t.incoming,
	}, nil
}

// unaryAuthInterceptor validates NodeID on unary calls.
func (t *GrpcTransport) unaryAuthInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if _, err := t.extractNodeID(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// streamAuthInterceptor validates NodeID on stream calls.
func (t *GrpcTransport) streamAuthInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if _, err := t.extractNodeID(ss.Context()); err != nil {
		return err
	}

	return handler(srv, ss)
}

// extractNodeID extracts and optionally verifies NodeID from gRPC metadata.
func (t *GrpcTransport) extractNodeID(ctx context.Context) (aether.NodeID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("grpc: missing metadata")
	}

	nodeIDs := md.Get(MetadataNodeID)
	if len(nodeIDs) == 0 {
		return "", errors.New("grpc: missing NodeID in metadata")
	}

	nodeID := aether.NodeID(nodeIDs[0])

	// Verify signature if present
	signatures := md.Get(MetadataSignature)
	if len(signatures) > 0 {
		sig, err := hex.DecodeString(signatures[0])
		if err != nil {
			return "", errors.New("grpc: invalid signature encoding")
		}

		// Get public key from dedicated header (NodeID is a base32 fingerprint, not a raw key)
		pubKeys := md.Get(MetadataPubKey)
		if len(pubKeys) == 0 {
			return "", errors.New("grpc: missing public key metadata")
		}
		pubKeyBytes, err := hex.DecodeString(pubKeys[0])
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			return "", errors.New("grpc: invalid public key")
		}
		pubKey := ed25519.PublicKey(pubKeyBytes)

		// Verify the NodeID derives from this public key
		derivedNodeID, err := aether.NewNodeID(pubKey)
		if err != nil || derivedNodeID != nodeID {
			return "", errors.New("grpc: public key does not match NodeID")
		}

		// Verify signature
		message := []byte(fmt.Sprintf("grpc-dial:%s:%s", nodeID, t.localNode))
		if !ed25519.Verify(pubKey, message, sig) {
			return "", errors.New("grpc: invalid signature")
		}
	}

	return nodeID, nil
}

// Server returns the gRPC server instance for cmux integration.
// Returns nil if Listen() or CreateServer() hasn't been called.
func (t *GrpcTransport) Server() *grpc.Server {
	return t.server
}

// Incoming returns the channel of incoming sessions from the transport service.
// Used by the runtime's accept loop to receive sessions from the cmux gRPC server.
func (t *GrpcTransport) Incoming() <-chan aether.IncomingSession {
	return t.incoming
}

// CreateServer creates the gRPC server without starting a listener.
// Use with cmux to serve gRPC on a shared port:
//
//	grpcServer := aether.CreateServer()
//	go grpcServer.Serve(cmuxGRPCListener)
func (t *GrpcTransport) CreateServer() *grpc.Server {
	if t.server != nil {
		return t.server
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(t.unaryAuthInterceptor),
		grpc.StreamInterceptor(t.streamAuthInterceptor),
	)
	t.server = server
	RegisterTransportService(server, t)
	return server
}

// Close shuts down the aether.
func (t *GrpcTransport) Close() error {
	if t.server != nil {
		t.server.GracefulStop()
	}
	close(t.incoming)
	return nil
}

// Protocol implements aether.ProtocolAdapter.
func (t *GrpcTransport) Protocol() aether.Protocol { return aether.ProtoGRPC }

// Compile-time interface check.
var _ aether.ProtocolAdapter = (*GrpcTransport)(nil)

// RegisterTransportService registers the transport service with a gRPC server.
// RegisterTransportService registers the mesh transport service on a gRPC server.
func RegisterTransportService(server *grpc.Server, t *GrpcTransport) {
	pb.RegisterTransportServiceServer(server, &transportServer{transport: t})
}

// transportServer implements the TransportService gRPC server.
type transportServer struct {
	pb.UnimplementedTransportServiceServer
	transport *GrpcTransport
}

// Stream handles a bidirectional streaming connection.
// Each Stream RPC becomes one mesh session (like one WebSocket connection).
// A pair of io.Pipe bridges the gRPC stream to a net.Conn for TCPSession.
func (s *transportServer) Stream(stream pb.TransportService_StreamServer) error {
	nodeID, err := s.transport.extractNodeID(stream.Context())
	if err != nil {
		return err
	}

	// Create pipe-based bridge: gRPC stream ↔ net.Conn
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()

	conn := &grpcPipeConn{
		reader: serverReader,
		writer: serverWriter,
		closer: func() error {
			serverWriter.Close()
			serverReader.Close()
			return nil
		},
	}

	// Pump: gRPC stream recv → serverReader (so TCPSession readLoop can read)
	go func() {
		defer clientWriter.Close()
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			if _, err := clientWriter.Write(frame.Data); err != nil {
				return
			}
		}
	}()

	// Pump: clientReader → gRPC stream send (so TCPSession writeLoop sends reach remote)
	go func() {
		defer clientReader.Close()
		buf := make([]byte, 65536)
		for {
			n, err := clientReader.Read(buf)
			if err != nil {
				return
			}
			if err := stream.Send(&pb.Frame{Data: buf[:n], Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
				return
			}
		}
	}()

	session := aether.NewConnection(s.transport.localNode, nodeID, conn)
	session.OnClose(func() { conn.Close() })

	select {
	case s.transport.incoming <- aether.IncomingSession{Session: session}:
	default:
		conn.Close()
		return errors.New("grpc: incoming session buffer full")
	}

	// Block until the stream context is done (keeps the gRPC stream alive)
	<-stream.Context().Done()
	return nil
}

// Ping implements the Ping RPC for health checks.
func (s *transportServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		ClientTimestampNs: req.TimestampNs,
		ServerTimestampNs: time.Now().UnixNano(),
		NodeId:            string(s.transport.localNode),
	}, nil
}

// grpcPipeConn wraps io.Pipe reader/writer as a net.Conn for TCPSession.
type grpcPipeConn struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	closer func() error
}

func (c *grpcPipeConn) Read(b []byte) (int, error)         { return c.reader.Read(b) }
func (c *grpcPipeConn) Write(b []byte) (int, error)        { return c.writer.Write(b) }
func (c *grpcPipeConn) Close() error                        { return c.closer() }
func (c *grpcPipeConn) LocalAddr() net.Addr                 { return grpcNetAddr{} }
func (c *grpcPipeConn) RemoteAddr() net.Addr                { return grpcNetAddr{} }
func (c *grpcPipeConn) SetDeadline(t time.Time) error       { return nil }
func (c *grpcPipeConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *grpcPipeConn) SetWriteDeadline(t time.Time) error  { return nil }

type grpcNetAddr struct{}

func (grpcNetAddr) Network() string { return "grpc" }
func (grpcNetAddr) String() string  { return "grpc" }

// GrpcListener implements aether.Listener for gRPC.
type GrpcListener struct {
	listener net.Listener
	server   *grpc.Server
	incoming chan aether.IncomingSession
}

// Accept waits for the next incoming session.
func (l *GrpcListener) Accept(ctx context.Context) (aether.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s, ok := <-l.incoming:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return s.Session, nil
	}
}

// Close stops listening.
func (l *GrpcListener) Close() error {
	l.server.GracefulStop()
	return nil
}

// Addr returns the local address.
func (l *GrpcListener) Addr() net.Addr {
	return l.listener.Addr()
}

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
}

// runClientStream manages the client-side bidirectional stream.
func (s *GrpcSession) runClientStream(ctx context.Context) {
	defer close(s.recvCh)

	// Create the bidi stream via the generated client
	client := pb.NewTransportServiceClient(s.conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		return
	}

	// Recv pump: stream → recvCh
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case s.recvCh <- frame.Data:
			case <-s.closeCh:
				return
			}
		}
	}()

	// Send pump: sendCh → stream
	for {
		select {
		case <-ctx.Done():
			stream.CloseSend()
			return
		case <-s.closeCh:
			stream.CloseSend()
			return
		case data, ok := <-s.sendCh:
			if !ok {
				stream.CloseSend()
				return
			}
			if err := stream.Send(&pb.Frame{Data: data, Type: pb.FrameType_FRAME_TYPE_DATA}); err != nil {
				return
			}
		}
	}
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

func (s *GrpcSession) NetConn() net.Conn { return nil } // gRPC doesn't expose raw net.Conn
func (s *GrpcSession) Protocol() aether.Protocol { return aether.ProtoGRPC }
func (s *GrpcSession) OnClose(fn func()) { /* gRPC handles lifecycle */ }
