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
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
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
	MetadataNodeID = "x-orbtr-nodeid"
	// MetadataSignature is the gRPC metadata key for signature
	MetadataSignature = "x-orbtr-signature"
	// MetadataPubKey is the gRPC metadata key for hex-encoded Ed25519 public key
	MetadataPubKey = "x-orbtr-pubkey"
	// MetadataNonce and MetadataTimestamp carry per-dial freshness so a
	// captured metadata set cannot be replayed (AER-032).
	MetadataNonce     = "x-orbtr-nonce"
	MetadataTimestamp = "x-orbtr-timestamp"
)

// grpcDialFreshnessWindow bounds clock skew between a dial signature's
// timestamp and the server's clock. A dial whose timestamp is outside this
// window, or whose nonce was already seen within it, is rejected (AER-032).
const grpcDialFreshnessWindow = 60 * time.Second

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
	closeOnce  sync.Once // AER-104: guard against double-close of incoming
	replay     *grpcDialReplayGuard // AER-032: per-dial nonce replay defense
}

// grpcDialReplayGuard rejects reuse of an authenticated dial nonce within the
// freshness window (AER-032). Mirrors the WebSocket transport's dialReplayGuard.
type grpcDialReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // nonce → expiry
}

func newGrpcDialReplayGuard() *grpcDialReplayGuard {
	return &grpcDialReplayGuard{seen: make(map[string]time.Time)}
}

// checkAndRecord returns true if the nonce is fresh (unseen within the
// window) and records it with the given expiry; false if it is a replay.
// Expired entries are swept on each call to bound memory.
func (g *grpcDialReplayGuard) checkAndRecord(nonce string, now, expiry time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
	if exp, ok := g.seen[nonce]; ok && now.Before(exp) {
		return false
	}
	g.seen[nonce] = expiry
	return true
}

// NewGrpcTransport creates a new gRPC transport. Returns (T, error)
// for signature symmetry with NewNoiseTransport / NewQuicTransport /
// NewWebsocketTransport — every Transport constructor in aether shares
// the same shape so a generic factory can wrap them all.
func NewGrpcTransport(cfg GrpcTransportConfig) (*GrpcTransport, error) {
	return &GrpcTransport{
		localNode:  cfg.LocalNode,
		privateKey: cfg.PrivateKey,
		listenAddr: cfg.ListenAddr,
		tlsConfig:  cfg.TLSConfig,
		incoming:   make(chan aether.IncomingSession, 32),
		replay:     newGrpcDialReplayGuard(),
	}, nil
}

// NewGrpcTransportFromConfig creates a gRPC transport from the unified Config.
// Returns (nil, nil) if Config.GRPC is nil (protocol disabled).
func NewGrpcTransportFromConfig(cfg aether.Config) (*GrpcTransport, error) {
	if cfg.GRPC == nil {
		return nil, nil
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

	// Create signed metadata to prove our identity. AER-032: bind a fresh
	// timestamp + random nonce into the signed message so a captured metadata
	// set cannot be replayed to impersonate this NodeID.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoGRPC, target.NodeID, err)
	}
	nonceStr := base64.RawStdEncoding.EncodeToString(nonce)
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	message := []byte(fmt.Sprintf("grpc-dial:%s:%s:%s:%s", t.localNode, target.NodeID, tsStr, nonceStr))
	signature := ed25519.Sign(t.privateKey, message)
	md := metadata.Pairs(
		MetadataNodeID, string(t.localNode),
		MetadataSignature, hex.EncodeToString(signature),
		MetadataPubKey, hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)),
		MetadataNonce, nonceStr,
		MetadataTimestamp, tsStr,
	)

	conn, err := grpc.DialContext(ctx, target.Address,
		t.dialCredentials(),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoGRPC, target.NodeID, err)
	}

	// AER-010: the identity metadata must ride the STREAM RPC — the server's
	// auth interceptor reads it off client.Stream(ctx), not off DialContext
	// (outgoing metadata on the dial ctx is dropped). It also must outlive the
	// caller's dial ctx: a customary `WithTimeout(...); defer cancel()` around
	// Dial would otherwise cancel the long-lived stream the instant the dial
	// timeout elapsed. Derive the stream ctx from Background, carry the
	// metadata on it, and cancel it from the session's Close.
	streamCtx, streamCancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), md))

	session := &GrpcSession{
		conn:         conn,
		localNode:    t.localNode,
		remoteNode:   target.NodeID,
		sendCh:       make(chan []byte, 64),
		recvCh:       make(chan []byte, 64),
		closeCh:      make(chan struct{}),
		streamCancel: streamCancel,
	}

	// Start stream goroutine
	go session.runClientStream(streamCtx)

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

// extractNodeID fully authenticates the caller's NodeID from gRPC metadata,
// including consuming the one-time dial nonce (replay defense). Used by the
// auth interceptors, which run once per stream.
func (t *GrpcTransport) extractNodeID(ctx context.Context) (aether.NodeID, error) {
	return t.extractNodeIDImpl(ctx, true)
}

// extractNodeIDVerified returns the authenticated NodeID WITHOUT re-consuming
// the dial nonce. The stream handler calls this after the interceptor has
// already gated the stream, so re-running the replay check would reject the
// legitimate second read of the same nonce (AER-032).
func (t *GrpcTransport) extractNodeIDVerified(ctx context.Context) (aether.NodeID, error) {
	return t.extractNodeIDImpl(ctx, false)
}

func (t *GrpcTransport) extractNodeIDImpl(ctx context.Context, checkReplay bool) (aether.NodeID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("grpc: missing metadata")
	}

	nodeIDs := md.Get(MetadataNodeID)
	if len(nodeIDs) == 0 {
		return "", errors.New("grpc: missing NodeID in metadata")
	}

	nodeID := aether.NodeID(nodeIDs[0])

	// NodeID ownership MUST be cryptographically proven — the signature is
	// mandatory, never optional-on-presence. A caller that omits it would
	// otherwise be accepted under any claimed NodeID (peer impersonation,
	// AE-C-03). There is no client-cert backstop that binds TLS identity to the
	// aether NodeID, so this signature is the sole ownership proof. Legitimate
	// clients always send it (see Dial), so requiring it breaks nothing.
	signatures := md.Get(MetadataSignature)
	if len(signatures) == 0 {
		return "", errors.New("grpc: missing signature — NodeID ownership unproven")
	}
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

	// AER-032: require a fresh timestamp + unseen nonce, and verify the
	// signature over BOTH. Without this the signature was over a static
	// message, so a captured (nodeid, sig, pubkey) triple replayed
	// indefinitely to open sessions impersonating the victim NodeID.
	nonces := md.Get(MetadataNonce)
	timestamps := md.Get(MetadataTimestamp)
	if len(nonces) == 0 || len(timestamps) == 0 {
		return "", errors.New("grpc: missing dial freshness (nonce/timestamp)")
	}
	nonceStr := nonces[0]
	tsStr := timestamps[0]
	tsNano, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", errors.New("grpc: invalid dial timestamp")
	}
	now := time.Now()
	if skew := now.Sub(time.Unix(0, tsNano)); skew > grpcDialFreshnessWindow || skew < -grpcDialFreshnessWindow {
		return "", errors.New("grpc: stale dial timestamp")
	}

	// Verify signature over the freshness-bound message (must match Dial).
	message := []byte(fmt.Sprintf("grpc-dial:%s:%s:%s:%s", nodeID, t.localNode, tsStr, nonceStr))
	if !ed25519.Verify(pubKey, message, sig) {
		return "", errors.New("grpc: invalid signature")
	}

	// Reject replays only after the signature proves authenticity, so a
	// forged nonce cannot evict a legitimate one from the guard. checkReplay
	// is false for the post-interceptor handler read so it doesn't reject the
	// legitimate second read of the same stream's nonce.
	if checkReplay && t.replay != nil &&
		!t.replay.checkAndRecord(nonceStr, now, time.Unix(0, tsNano).Add(grpcDialFreshnessWindow)) {
		return "", errors.New("grpc: replayed dial nonce")
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
	// AER-104: GracefulStop drains active handlers before we close the
	// producer-visible incoming channel, and closeOnce makes a second Close
	// a no-op instead of panicking on a double close(t.incoming).
	t.closeOnce.Do(func() {
		if t.server != nil {
			t.server.GracefulStop()
		}
		close(t.incoming)
	})
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
	nodeID, err := s.transport.extractNodeIDVerified(stream.Context())
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

	cancel()      // abort a recv pump blocked in stream.Recv()
	<-recvDone    // join it
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

func (s *GrpcSession) NetConn() net.Conn { return nil } // gRPC doesn't expose raw net.Conn
func (s *GrpcSession) Protocol() aether.Protocol { return aether.ProtoGRPC }
func (s *GrpcSession) OnClose(fn func()) { /* gRPC handles lifecycle */ }
