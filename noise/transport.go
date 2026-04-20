//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	vl1 "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/nat"
	"github.com/ORBTR/aether/relay"
	
)

const (
	noiseDefaultHandshake = 5 * time.Second
	noiseDefaultMaxPacket = 64 * 1024
)

// dialOverride carries per-dial scope context for shared transports.
type dialOverride struct {
	ScopeID string
	Keys     [][]byte
}

type dialOverrideKeyT struct{}

// WithDialOverride injects scope-specific keys into a dial context.
// Used by SharedTransport to tell the underlying NoiseTransport which
// scope keys and preamble to use for the handshake.
func WithDialOverride(ctx context.Context, scopeID string, keys [][]byte) context.Context {
	return context.WithValue(ctx, dialOverrideKeyT{}, &dialOverride{ScopeID: scopeID, Keys: keys})
}

func getDialOverride(ctx context.Context) *dialOverride {
	v, _ := ctx.Value(dialOverrideKeyT{}).(*dialOverride)
	return v
}

// TenantKeyResolver resolves network keys by scope ID for shared transports.
// When set on a NoiseTransport, the listener detects preamble-bearing packets
// and delegates PSK selection to this resolver instead of the static keyMap.
type TenantKeyResolver interface {
	// ResolveKeys returns the network keys (PSKs) for the given scope.
	// The first key is used for the Noise prologue. Returns an error if
	// the scope is unknown or has no keys registered.
	ResolveKeys(scopeID string) ([][]byte, error)
}

// NoiseTransportConfig contains the identity material and knobs required to
// construct a Noise-based VL1 aether.
type NoiseTransportConfig struct {
	LocalNode        aether.NodeID
	PrivateKey       ed25519.PrivateKey
	NetworkKeys      []string // List of valid network keys (PSK). First one is used for sending.
	HandshakeTimeout time.Duration
	MaxPacketSize    int
	STUNConfig       aether.STUNConfig // Optional STUN configuration for NAT detection
	RelayConfig      relay.RelayConfig    // Optional Relay configuration
	ListenAddr       string               // Address to listen on (e.g., ":0", ":41641")
	RateLimitBurst   int                  // Rate limit burst size (0 = default 100)
	RateLimitRate    int                  // Rate limit rate per second (0 = default 1000)

	// UDP socket buffer sizes. Zero = OS default.
	UDPReadBuffer  int // Read buffer size in bytes (default 4 MB)
	UDPWriteBuffer int // Write buffer size in bytes (default 2 MB)

	// Session tuning
	NonceWindowSize int     // Explicit nonce sliding window size (default 64)
	HealthEMAAlpha  float64 // RTT exponential moving average smoothing factor (default 0.2)
	InboxSize       int     // Per-session inbox channel capacity (default DefaultInboxSize=128)

	// BindResolver resolves platform-specific bind addresses for UDP.
	// When set, Listen() uses this to determine the bind address.
	// When nil, Listen() uses ListenAddr directly (defaults to 0.0.0.0).
	BindResolver aether.BindAddressResolver

	// TenantKeyResolver enables preamble mode for shared multi-scope transports.
	// When set, the listener detects and processes scope preambles in handshake
	// packets. When nil, the transport operates in dedicated (single-scope) mode.
	TenantKeyResolver TenantKeyResolver

	// ScopeLimiterConfig configures per-scope rate limiting for relay traffic.
	// Only effective when relay is enabled and transport is shared (multi-scope).
	ScopeLimiterConfig ScopeLimiterConfig

	// RequireRetryToken enables the QUIC-style stateless retry path (S3 —
	// _SECURITY.md §3.1). When true, the listener responds to first-contact
	// handshake initiations with a small RETRY cookie instead of computing
	// Noise state, eliminating reflection amplification. The initiator must
	// echo the cookie in its next attempt.
	//
	// The field is a *bool so the zero-value (nil) distinguishes "caller
	// left it unset" (→ default = ON) from "caller explicitly turned it off"
	// (→ false). Set to `BoolPtr(false)` if you need to disable for interop
	// with legacy initiators that don't handle 0xFE retry prefix.
	RequireRetryToken *bool
}

// BoolPtr returns a pointer to the given bool. Useful for explicitly
// disabling tri-state config fields like RequireRetryToken.
func BoolPtr(b bool) *bool { return &b }

// requireRetryTokenDefault is the production default — enabled. Amplification
// protection is meaningless unless it's on by default; operators opting out
// is the exception path, not the norm.
const requireRetryTokenDefault = true

// resolveRetryTokenDefault implements the tri-state for RequireRetryToken:
// nil → default (requireRetryTokenDefault), non-nil → caller's choice.
func resolveRetryTokenDefault(p *bool) bool {
	if p == nil {
		return requireRetryTokenDefault
	}
	return *p
}

// NoiseTransport implements the Transport interface by performing a Noise XX/XK
// handshake over UDP and encrypting subsequent datagrams with ChaCha20-Poly1305.
//
// Restructured: crypto identity, key management, and peer caching are extracted
// into reusable services.
type NoiseTransport struct {
	// Extracted services
	identity   *transportCrypto.Identity         // Ed25519 + Curve25519 identity
	keyManager *transportCrypto.NetworkKeyManager // network key rotation + CRC32 lookup
	peerCache  *transportCrypto.PeerKeyCache      // peer static key cache (XK reconnections)

	// Convenience aliases (derived from identity — avoids .identity.X everywhere)
	localNode  aether.NodeID
	edPriv     ed25519.PrivateKey
	edPub      ed25519.PublicKey
	staticPriv []byte
	staticPub  []byte

	// Handshake + transport config
	tenantKeyResolver TenantKeyResolver
	handshake         time.Duration
	maxPacket         int
	listenAddr        string

	// NAT/STUN
	stun     *nat.STUNClient
	stunTx   map[string]chan *stun.Message
	stunMu   sync.Mutex
	stunConn *net.UDPConn

	// Relay
	relayConfig   relay.RelayConfig
	relayService  *relay.RelayService
	scopeLimiter *TenantRelayLimiter

	// Rate limiting
	rateLimiter *tokenBucket    // Global handshake budget
	sourceLimit *sourceLimiter  // Per-source-IP budget (S6 — _SECURITY.md §3.1)

	// Source validation — issues stateless retry tokens to first-contact
	// addresses when requireRetryToken is true. Concern S3.
	retryGuard        *retryGuard
	requireRetryToken bool

	// Sessions
	listener         *noiseListener
	listenerMu       sync.Mutex
	outgoingSessions map[string]*noiseConn
	outgoingMu       sync.Mutex

	// Platform + tuning
	bindResolver   aether.BindAddressResolver
	udpReadBuffer  int
	udpWriteBuffer int
	nonceWindow    int
	healthAlpha    float64
	inboxSize      int
	ticketStore      *TicketStore
	initiatorTickets *initiatorTicketCache // initiator-side resume cache
	seenTickets      *seenTicketCache      // responder-side replay guard
}

// NewNoiseTransport builds a Noise transport using the provided config.
func NewNoiseTransport(cfg NoiseTransportConfig) (*NoiseTransport, error) {
	// --- Create extracted services ---
	id, err := transportCrypto.NewIdentity(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("vl1: identity: %w", err)
	}
	if cfg.LocalNode != "" && cfg.LocalNode != id.NodeID {
		return nil, errors.New("vl1: config LocalNode mismatch")
	}

	km, err := transportCrypto.NewNetworkKeyManager(cfg.NetworkKeys)
	if err != nil {
		return nil, fmt.Errorf("vl1: network keys: %w", err)
	}

	pc := transportCrypto.NewPeerKeyCache(4 * time.Hour) // TTL-based eviction

	// --- Config defaults ---
	handshake := cfg.HandshakeTimeout
	if handshake == 0 {
		handshake = noiseDefaultHandshake
	}
	maxPacket := cfg.MaxPacketSize
	if maxPacket <= 0 {
		maxPacket = noiseDefaultMaxPacket
	}
	var stunClient *nat.STUNClient
	if cfg.STUNConfig.Enabled {
		stunClient = nat.NewSTUNClient(cfg.STUNConfig)
	}
	rateLimitBurst := cfg.RateLimitBurst
	if rateLimitBurst <= 0 {
		rateLimitBurst = 100
	}
	rateLimitRate := cfg.RateLimitRate
	if rateLimitRate <= 0 {
		rateLimitRate = 1000
	}
	udpReadBuf := cfg.UDPReadBuffer
	if udpReadBuf <= 0 {
		udpReadBuf = 4 * 1024 * 1024
	}
	udpWriteBuf := cfg.UDPWriteBuffer
	if udpWriteBuf <= 0 {
		udpWriteBuf = 2 * 1024 * 1024
	}
	nonceWin := cfg.NonceWindowSize
	if nonceWin <= 0 {
		nonceWin = 64
	}
	healthAlpha := cfg.HealthEMAAlpha
	if healthAlpha <= 0 || healthAlpha > 1 {
		healthAlpha = 0.2
	}
	inboxSize := cfg.InboxSize
	if inboxSize <= 0 {
		inboxSize = vl1.DefaultInboxSize
	}

	t := &NoiseTransport{
		// Extracted services
		identity:   id,
		keyManager: km,
		peerCache:  pc,

		// Convenience aliases from identity
		localNode:  id.NodeID,
		edPriv:     id.Ed25519Priv,
		edPub:      id.Ed25519Pub,
		staticPriv: id.Curve25519Priv,
		staticPub:  id.Curve25519Pub,

		// Config
		tenantKeyResolver: cfg.TenantKeyResolver,
		handshake:         handshake,
		maxPacket:         maxPacket,
		listenAddr:        cfg.ListenAddr,

		// NAT/STUN
		stun:   stunClient,
		stunTx: make(map[string]chan *stun.Message),

		// Relay
		relayConfig:   cfg.RelayConfig,
		scopeLimiter: NewTenantRelayLimiter(cfg.ScopeLimiterConfig),

		// Rate limiting — global + per-source (S6)
		rateLimiter: newTokenBucket(float64(rateLimitBurst), float64(rateLimitRate), time.Second),
		sourceLimit: newSourceLimiter(SourceLimitDefaultBurst, SourceLimitDefaultRate, SourceLimitMaxEntries),

		// Source-validation cookies (S3) — guard always exists so peers
		// can opt in by sending cookies; enforcement gated on the flag.
		// Tri-state nil → default (on); explicit *false disables for
		// legacy-initiator interop.
		retryGuard:        newRetryGuard(),
		requireRetryToken: resolveRetryTokenDefault(cfg.RequireRetryToken),

		// Sessions
		outgoingSessions: make(map[string]*noiseConn),

		// Platform + tuning
		bindResolver:   cfg.BindResolver,
		udpReadBuffer:  udpReadBuf,
		udpWriteBuffer: udpWriteBuf,
		nonceWindow:    nonceWin,
		healthAlpha:    healthAlpha,
		inboxSize:      inboxSize,
	}

	// Initialize relay service (external session management + forwarding).
	// SessionIndex is set to t itself after construction — NoiseTransport implements
	// relay.SessionIndex via LookupByNodeID and LookupExternal.
	t.relayService = relay.NewRelayService(cfg.RelayConfig, nil)
	t.relayService.SetSessionIndex(t)

	// Initialize session ticket store for resumption
	ticketStore, ticketErr := NewTicketStore()
	if ticketErr == nil {
		t.ticketStore = ticketStore
	}
	// Initiator-side resume cache and responder-side replay guard.
	// Kept independent of the ticket key store — these are in-memory
	// only and have no cryptographic secrets.
	t.initiatorTickets = newInitiatorTicketCache(DefaultTicketCacheSize)
	t.seenTickets = newSeenTicketCache(DefaultSeenTicketCacheSize)
	return t, nil
}

// NewNoiseTransportFromConfig creates a Noise transport from the unified Config.
// Returns nil if Config.Noise is nil (protocol disabled).
func NewNoiseTransportFromConfig(cfg aether.Config) (*NoiseTransport, error) {
	if cfg.Noise == nil {
		return nil, nil
	}
	nc := cfg.Noise
	return NewNoiseTransport(NoiseTransportConfig{
		LocalNode:        cfg.NodeID,
		PrivateKey:       cfg.PrivateKey,
		ListenAddr:       nc.ListenAddr,
		HandshakeTimeout: nc.HandshakeTimeout,
		MaxPacketSize:    nc.MaxPacketSize,
		UDPReadBuffer:    nc.UDPReadBuffer,
		UDPWriteBuffer:   nc.UDPWriteBuffer,
		NonceWindowSize:  nc.NonceWindowSize,
		HealthEMAAlpha:   nc.HealthEMAAlpha,
		RateLimitBurst:   nc.RateLimitBurst,
		RateLimitRate:    nc.RateLimitRate,
		InboxSize:        nc.InboxSize,
		STUNConfig:       cfg.STUN,
		BindResolver:     cfg.BindResolver,
	})
}

// Dial establishes a Noise session to the provided target using the shared
// listener socket. This ensures all UDP traffic flows through port 41641,
// making NAT traversal and session multiplexing work correctly.
func (t *NoiseTransport) Dial(ctx context.Context, target aether.Target) (aether.Connection, error) {
	network := "udp"
	if strings.Contains(target.Address, "[") {
		network = "udp6"
	}

	addr, err := net.ResolveUDPAddr(network, target.Address)
	if err != nil {
		return nil, err
	}

	// Require listener to be started — we use its shared socket
	t.listenerMu.Lock()
	listener := t.listener
	t.listenerMu.Unlock()
	if listener == nil || t.stunConn == nil {
		return nil, fmt.Errorf("noise: listener not started (call Listen before Dial)")
	}

	path := vl1.Path{
		Address: addr,
		NodeID:  target.NodeID,
	}

	// Attempt 0.5-RTT resume before full handshake. Skips the XK/XX
	// round-trip entirely when a valid ticket is cached for this peer.
	// If the responder rejects (expired, key rotated, replay) or the
	// request times out, we fall through to the full handshake path.
	// No 0-RTT application data is piggybacked — this is strictly key
	// resumption, so rollback is safe.
	if t.initiatorTickets != nil && listener.conn != nil {
		if nc, rerr := t.tryResumeDial(ctx, target, listener.conn, addr); rerr == nil && nc != nil {
			// Register in the listener's session table so subsequent
			// inbound packets route to this conn. Key format matches
			// what dispatchToSession expects (addr.String()).
			listener.mu.Lock()
			listener.sessions.Put(target.NodeID, addr.String(), "", &noiseConnSession{conn: nc, nodeID: target.NodeID})
			listener.mu.Unlock()
			dbgHandshake.Printf("Resumed session with %s via cached ticket", target.NodeID.Short())
			return aether.NewConnection(t.localNode, target.NodeID, nc), nil
		}
		// Any error (rejected, timeout, tag mismatch) → fall through.
		// tryResumeDial evicts the cache entry on explicit reject so we
		// don't loop attempting a dead ticket.
	}

	session, err := t.performInitiatorHandshakeShared(ctx, listener, addr, path)
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoNoise, target.NodeID, err)
	}
	return session, nil
}

// Listen starts accepting Noise sessions on the configured UDP address.
// Supports dual-stack: when the platform resolver provides both IPv4 and IPv6
// bind addresses, two separate sockets are opened. Both feed into the same
// Noise session handler. IPv4 handles public traffic, IPv6 handles private
// same-origin traffic (e.g., fdaa: on Fly).
func (t *NoiseTransport) Listen(ctx context.Context) (aether.Listener, error) {
	addrStr := t.listenAddr
	if addrStr == "" {
		addrStr = ":0"
	}

	// Check for dual-stack bind addresses
	var ipv4Addr, ipv6Addr string
	if t.bindResolver != nil {
		_, portStr, _ := net.SplitHostPort(addrStr)
		port := 0
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}
		ipv4Addr, ipv6Addr = t.bindResolver.ResolveUDPBindDualStack(port)
		if ipv4Addr == "" && ipv6Addr == "" {
			// Fallback to single bind
			addrStr = t.bindResolver.ResolveUDPBind(port)
		}
	}

	// Open primary socket
	var primaryConn *net.UDPConn
	if ipv4Addr != "" {
		// Dual-stack: IPv4 primary (public traffic)
		// Platform handles bind semantics (e.g., Fly's eBPF proxy needs ListenPacket).
		var err error
		if t.bindResolver != nil {
			primaryConn, err = t.bindResolver.OpenUDPListener("udp", ipv4Addr)
		} else {
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp4", ipv4Addr)
			if err == nil {
				primaryConn, err = net.ListenUDP("udp4", addr)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("listen IPv4 %s: %w", ipv4Addr, err)
		}
		log.Printf("[NOISE] IPv4 listener started on %s", primaryConn.LocalAddr())
	} else {
		// Single socket (dual-stack by default on most platforms)
		addr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			return nil, aether.WrapOp("listen", aether.ProtoNoise, "", err)
		}
		primaryConn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return nil, aether.WrapOp("listen", aether.ProtoNoise, "", err)
		}
	}

	_ = primaryConn.SetReadBuffer(t.udpReadBuffer)
	_ = primaryConn.SetWriteBuffer(t.udpWriteBuffer)

	l := &noiseListener{
		transport:  t,
		conn:       primaryConn,
		handshakes: make(map[string]*listenerHandshake),
		sessions:   aether.NewConnectionMap(),
		incoming:   make(chan aether.IncomingSession, 32),
	}
	// Store connection reference in transport for STUN sending
	t.stunConn = primaryConn

	// Create QUIC demux for UDP port multiplexing
	l.quicDemux = NewDemuxPacketConn(primaryConn)

	// Dual-stack: open IPv6 listener and forward packets to primary handler
	if ipv6Addr != "" {
		ipv6UDPAddr, err := net.ResolveUDPAddr("udp6", ipv6Addr)
		if err != nil {
			primaryConn.Close()
			return nil, fmt.Errorf("resolve IPv6 bind %s: %w", ipv6Addr, err)
		}
		ipv6Conn, err := net.ListenUDP("udp6", ipv6UDPAddr)
		if err != nil {
			// IPv6 listener is optional — log warning but continue with IPv4 only
			log.Printf("[NOISE] Warning: IPv6 listener failed on %s: %v (continuing IPv4-only)", ipv6Addr, err)
		} else {
			_ = ipv6Conn.SetReadBuffer(t.udpReadBuffer)
			_ = ipv6Conn.SetWriteBuffer(t.udpWriteBuffer)
			l.ipv6Conn = ipv6Conn
			l.quicDemux.ipv6Conn = ipv6Conn // QUIC writes to IPv6 targets use this socket
			log.Printf("[NOISE] IPv6 listener started on %s", ipv6Conn.LocalAddr())
		}
	}

	t.listenerMu.Lock()
	t.listener = l
	t.listenerMu.Unlock()

	go l.run(ctx)
	return l, nil
}

// QUICPacketConn returns a net.PacketConn that receives QUIC packets from the
// shared UDP port. Use this to create a quic.Transport on the same port as Noise.
// Returns nil if the listener hasn't been started.
func (t *NoiseTransport) QUICPacketConn() net.PacketConn {
	t.listenerMu.Lock()
	l := t.listener
	t.listenerMu.Unlock()
	if l == nil {
		return nil
	}
	return l.quicDemux
}

// PeerRTT holds the measured round-trip time for a specific peer.
type PeerRTT struct {
	NodeID aether.NodeID
	RTT    time.Duration
}

// ActivePeerLatencies returns the average RTT for each active peer session.
// This uses the ping/pong EMA tracked by the session health monitor.
func (t *NoiseTransport) ActivePeerLatencies() []PeerRTT {
	t.listenerMu.Lock()
	l := t.listener
	t.listenerMu.Unlock()
	if l == nil {
		return nil
	}

	all := l.sessions.All()
	result := make([]PeerRTT, 0, len(all))
	for nodeID, sess := range all {
		if nc := connFromSession(sess); nc != nil {
			result = append(result, PeerRTT{
				NodeID: nodeID,
				RTT:    func() time.Duration { _, avg := nc.RTT(); return avg }(),
			})
		}
	}
	return result
}

// Send writes an encrypted datagram over the session.
func (t *NoiseTransport) Send(ctx context.Context, session aether.Connection, payload []byte) error {
	nc, err := extractNoiseConn(session)
	if err != nil {
		return err
	}
	return nc.sendPayload(ctx, payload)
}

// Receive reads and decrypts a datagram from the session.
func (t *NoiseTransport) Receive(ctx context.Context, session aether.Connection) ([]byte, error) {
	nc, err := extractNoiseConn(session)
	if err != nil {
		return nil, err
	}
	return nc.receive(ctx)
}

// Close is a no-op for the shared Noise transport instance.
func (t *NoiseTransport) Close() error { return nil }

// Protocol implements aether.ProtocolAdapter.
func (t *NoiseTransport) Protocol() aether.Protocol { return aether.ProtoNoise }

// SupportsRelay returns true if relay is enabled on this aether.
func (t *NoiseTransport) SupportsRelay() bool { return t.relayConfig.Enabled }

// Compile-time interface checks.
var _ aether.ProtocolAdapter = (*NoiseTransport)(nil)
var _ aether.RelayCapable = (*NoiseTransport)(nil)
var _ relay.SessionIndex = (*NoiseTransport)(nil)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// relay.SessionIndex implementation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// LookupByNodeID implements relay.SessionIndex — finds a Noise session by peer
// NodeID and wraps it in a aether.Connection for relay forwarding.
func (t *NoiseTransport) LookupByNodeID(id aether.NodeID) aether.Connection {
	nc := t.findNoiseSession(id)
	if nc == nil {
		return nil
	}
	return aether.NewConnection(t.localNode, id, nc)
}

// LookupExternal implements relay.SessionIndex — delegates to RelayService's
// external session map.
func (t *NoiseTransport) LookupExternal(id aether.NodeID) aether.Connection {
	if t.relayService == nil {
		return nil
	}
	return t.relayService.LookupExternal(id)
}

// RelayService returns the underlying relay service for direct access.
func (t *NoiseTransport) RelayService() *relay.RelayService {
	return t.relayService
}

// DiscoverReflexiveAddr discovers the public IP:port for a local address using STUN
func (t *NoiseTransport) DiscoverReflexiveAddr(ctx context.Context, localAddr *net.UDPAddr) (*aether.ReflexiveAddress, error) {
	if t.stun == nil {
		return nil, errors.New("vl1: STUN not enabled")
	}

	// If we have an active listener (stunConn), use it for multiplexing
	if t.stunConn != nil {
		return t.discoverReflexiveAddrMultiplexed(ctx)
	}

	// Fallback to creating a new connection (only works if not listening on same port)
	return t.stun.DiscoverReflexiveAddr(ctx, localAddr)
}

func (t *NoiseTransport) discoverReflexiveAddrMultiplexed(ctx context.Context) (*aether.ReflexiveAddress, error) {
	// Create STUN message
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	txID := string(msg.TransactionID[:])

	// Register transaction
	ch := make(chan *stun.Message, 1)
	t.stunMu.Lock()
	t.stunTx[txID] = ch
	t.stunMu.Unlock()

	defer func() {
		t.stunMu.Lock()
		delete(t.stunTx, txID)
		t.stunMu.Unlock()
	}()

	// Send to STUN servers
	servers := t.stun.Config().Servers
	if len(servers) == 0 {
		return nil, errors.New("vl1: no STUN servers configured")
	}

	// Send to all configured servers (scatter-gather)
	// The first valid response received will be used.
	for _, server := range servers {
		serverAddr, err := net.ResolveUDPAddr("udp", server)
		if err != nil {
			continue
		}
		// Best-effort send; ignore errors for individual servers
		_, _ = t.stunConn.WriteToUDP(msg.Raw, serverAddr)
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-ch:
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(resp); err != nil {
			return nil, err
		}
		return &aether.ReflexiveAddress{
			IP:         xorAddr.IP,
			Port:       xorAddr.Port,
			Discovered: time.Now(),
		}, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("vl1: STUN timeout")
	}
}

// handleSTUNPacket processes an incoming STUN packet
func (t *NoiseTransport) handleSTUNPacket(data []byte) {
	msg := new(stun.Message)
	msg.Raw = append([]byte(nil), data...)
	if err := msg.Decode(); err != nil {
		return
	}

	txID := string(msg.TransactionID[:])
	t.stunMu.Lock()
	ch, ok := t.stunTx[txID]
	t.stunMu.Unlock()

	if ok {
		select {
		case ch <- msg:
		default:
		}
	}
}

// DetectNATType performs comprehensive NAT type detection
func (t *NoiseTransport) DetectNATType(ctx context.Context, localAddr *net.UDPAddr) (aether.NATType, error) {
	if t.stun == nil {
		return aether.NATUnknown, errors.New("vl1: STUN not enabled")
	}
	return t.stun.DetectNATType(ctx, localAddr)
}

// GetSTUNClient returns the underlying STUN client (may be nil if STUN disabled)
func (t *NoiseTransport) GetSTUNClient() *nat.STUNClient {
	return t.stun
}

// RotateKeys atomically replaces the transport's network keys and keyMap.
// The first key in the slice is the active key (used for outbound handshakes);
// additional keys are accepted for inbound (supporting dual-key overlap during rotation).
func (t *NoiseTransport) RotateKeys(keys [][]byte) error {
	return t.keyManager.Rotate(keys)
}

// CurrentKeys returns a copy of the transport's current network keys.
// The first key is the active key used for outbound handshakes.
func (t *NoiseTransport) CurrentKeys() [][]byte {
	return t.keyManager.AllKeys()
}

// cachePeerKey stores a peer's Curve25519 static public key after a successful
// handshake. Subsequent dials to the same NodeID can use Noise XK instead of XX,
// providing encrypted msg1 and faster identity verification.
func (t *NoiseTransport) cachePeerKey(nodeID aether.NodeID, curvePublic []byte) {
	t.peerCache.Put(nodeID, curvePublic)
}

// lookupPeerKey retrieves a cached Curve25519 static public key for a peer.
// Returns nil if no key is cached (first contact — must use XX).
func (t *NoiseTransport) lookupPeerKey(nodeID aether.NodeID) []byte {
	return t.peerCache.Get(nodeID)
}

// evictPeerKey removes a cached peer key (e.g., after XK handshake failure
// due to key rotation). The next dial will fall back to XX.
func (t *NoiseTransport) evictPeerKey(nodeID aether.NodeID) {
	t.peerCache.Evict(nodeID)
}
