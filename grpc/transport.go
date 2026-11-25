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
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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
	// captured metadata set cannot be replayed (extractNodeIDImpl).
	MetadataNonce     = "x-orbtr-nonce"
	MetadataTimestamp = "x-orbtr-timestamp"
)

// grpcDialFreshnessWindow bounds clock skew between a dial signature's
// timestamp and the server's clock. A dial whose timestamp is outside this
// window, or whose nonce was already seen within it, is rejected.
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
	closeOnce  sync.Once            // Close closes incoming once
	replay     *grpcDialReplayGuard // per-dial nonce replay defense (extractNodeIDImpl)
}

// grpcDialReplayGuard rejects reuse of an authenticated dial nonce within the
// freshness window. Mirrors the WebSocket transport's dialReplayGuard.
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

	// Create signed metadata to prove our identity. Bind a fresh
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

	// passthrough hands the address to the dialer as it is, as DialContext did,
	// instead of NewClient's default dns resolution.
	conn, err := grpc.NewClient("passthrough:///"+target.Address, t.dialCredentials())
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoGRPC, target.NodeID, err)
	}
	if err := waitReady(ctx, conn); err != nil {
		// The dial has failed with err; the unused client's close adds nothing to it.
		_ = conn.Close()
		return nil, aether.WrapOp("dial", aether.ProtoGRPC, target.NodeID, err)
	}

	// The identity metadata must ride the STREAM RPC — the server's
	// auth interceptor reads it off client.Stream(ctx), not off DialContext
	// (outgoing metadata on the dial ctx is dropped). It also must outlive the
	// caller's dial ctx: a customary `WithTimeout(...); defer cancel()` around
	// Dial would otherwise cancel the long-lived stream the instant the dial
	// timeout elapsed. Derive the stream ctx from Background, carry the
	// metadata on it, and cancel it from the session's Close.
	streamCtx, streamCancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), md))

	session := newClientSession(streamCancel)
	session.conn = conn
	session.localNode = t.localNode
	session.remoteNode = target.NodeID

	// Start stream goroutine
	go session.runClientStream(streamCtx)

	return session, nil
}

// waitReady connects conn and waits until it is ready or ctx ends, so Dial
// returns a connection that reached the peer, or the reason it did not: the
// identity metadata rides the first stream (runClientStream), which needs a
// connected client to start.
func waitReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if !conn.WaitForStateChange(ctx, state) {
			return ctx.Err()
		}
	}
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
		// Serve answers nil once Stop or GracefulStop ends it; any other end is
		// a listener that has stopped accepting, which nothing else reports.
		if err := server.Serve(lis); err != nil {
			log.Printf("[GRPC] serve on %s ended: %v", lis.Addr(), err)
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
// legitimate second read of the same nonce.
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
	// otherwise be accepted under any claimed NodeID (peer impersonation).
	// There is no client-cert backstop that binds TLS identity to the
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

	// Require a fresh timestamp + unseen nonce, and verify the signature
	// over BOTH: a signature over a static message would let a captured
	// (nodeid, sig, pubkey) triple be replayed indefinitely to open
	// sessions impersonating the victim NodeID.
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
	// Install server TLS credentials when a TLS config was supplied, matching
	// Listen(): a plaintext server for a secure endpoint would contradict the
	// encrypted capability aether.CapabilitiesForConnection reports for it.
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(t.unaryAuthInterceptor),
		grpc.StreamInterceptor(t.streamAuthInterceptor),
	}
	if t.tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(t.tlsConfig)))
	}
	server := grpc.NewServer(opts...)
	t.server = server
	RegisterTransportService(server, t)
	return server
}

// Close shuts down the aether.
func (t *GrpcTransport) Close() error {
	// GracefulStop drains active handlers before we close the
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

// Ping implements the Ping RPC for health checks.
func (s *transportServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		ClientTimestampNs: req.TimestampNs,
		ServerTimestampNs: time.Now().UnixNano(),
		NodeId:            string(s.transport.localNode),
	}, nil
}

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
