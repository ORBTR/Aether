//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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

	aether "github.com/ORBTR/aether"
	vl1 "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	"github.com/ORBTR/aether/relay"
)

const (
	noiseDefaultHandshake = 5 * time.Second
	noiseDefaultMaxPacket = 64 * 1024
)

// dialOverride carries per-dial scope context for shared transports.
type dialOverride struct {
	ScopeID string
	Keys    [][]byte
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

// PartitionKeyResolver resolves network keys by scope ID for shared transports.
// When set on a NoiseTransport, the listener detects preamble-bearing packets
// and delegates PSK selection to this resolver instead of the static keyMap.
type PartitionKeyResolver interface {
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
	RelayConfig      relay.RelayConfig // Optional Relay configuration
	ListenAddr       string            // Address to listen on (e.g., ":0", ":41641")
	RateLimitBurst   int               // Rate limit burst size (0 = default 100)
	RateLimitRate    int               // Rate limit rate per second (0 = default 1000)

	// STUN is the STUN client a NAT-traversing host composes (nat.NewSTUNClient
	// is one). When it is nil and STUNConfig.Enabled is set, NewNoiseTransport
	// builds one through aether.NewSTUNClient, which the linked nat package
	// provides, and refuses with aether.ErrSTUNNotComposed when no STUN
	// implementation is linked. With neither, the transport runs no STUN, and
	// this package links none: it imports no STUN or NAT traversal code, so a
	// host that only dials carries none.
	STUN aether.STUNClient

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

	// PartitionKeyResolver enables preamble mode for shared multi-scope transports.
	// When set, the listener detects and processes scope preambles in handshake
	// packets. When nil, the transport operates in dedicated (single-scope) mode.
	PartitionKeyResolver PartitionKeyResolver

	// ScopeLimiterConfig configures per-scope rate limiting for relay traffic.
	// Only effective when relay is enabled and transport is shared (multi-scope).
	ScopeLimiterConfig ScopeLimiterConfig

	// RequireRetryToken enables the QUIC-style stateless retry path
	// (retryGuard). When true, the listener responds to first-contact
	// handshake initiations with a small RETRY cookie instead of computing
	// Noise state, eliminating reflection amplification. The initiator must
	// echo the cookie in its next attempt.
	//
	// The field is a *bool so the zero-value (nil) distinguishes "caller
	// left it unset" (→ default = ON) from "caller explicitly turned it off"
	// (→ false). Set to `BoolPtr(false)` to disable it for an initiator that
	// does not read the 0xFE retry prefix (handleHandshake issues the token
	// only while requireRetryToken is set).
	RequireRetryToken *bool

	// EnableResume opts in to 0.5-RTT session resumption (ticket store +
	// initiator cache + 0xFA resume packets). Off by default: the initiator
	// resume path (tryResumeDial) reads and arms a deadline on the SHARED
	// listener socket, which deafens the whole transport while it waits, and
	// the resumed conn's write and close target that shared socket. While it
	// is off NewNoiseTransport leaves the resume machinery nil, so
	// tryResumeDial and ticket issuance short-circuit.
	// TODO: route the resume path through the listener demux.
	// TODO, identity on the ticket path: DecryptTicket reads PeerID as the
	// whole 32-byte field of the ticket plaintext while IssueTicket writes a
	// canonical 30-byte NodeID into it, so the PeerID handleResumePacket
	// registers in l.sessions and reports through aether.NewConnection carries
	// two trailing NUL bytes and matches no canonical NodeID lookup; and
	// handleResumePacket builds the resumed conn with no remoteIdentity, so
	// RemoteIdentity is nil on it. Trim the field to the NodeID and carry the
	// identity key in the ticket.
	// TODO, scope on the ticket path: tryResumeDial reads no dial override,
	// initiatorTickets is keyed by peer alone, resumeMaterial carries no
	// scope, and Dial registers the resumed conn in listener.sessions with
	// scope "" and leaves nc.scopeID empty, so a shared transport's resumed
	// dial reads as dedicated to resolveRelayTarget and scopeAllowed. Carry
	// the scope in the material, key the cache by scope and peer, and set the
	// resumed conn's scope.
	EnableResume bool

	// WireVersions are the application's entries of the wire version offer
	// this transport's handshakes send; aether adds its own (see
	// aether.LocalWireVersions) and never reads the application's. Every
	// handshake chooses from this offer and the peer's and refuses before a
	// connection exists when a required entry has no common version. An entry
	// that names one of aether's or is not in canonical form fails
	// NewNoiseTransport.
	WireVersions aether.WireVersions
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
	identity   *transportCrypto.Identity          // Ed25519 + Curve25519 identity
	keyManager *transportCrypto.NetworkKeyManager // network key rotation + CRC32 lookup
	peerCache  *transportCrypto.PeerKeyCache      // peer static key cache (XK reconnections)

	// Convenience aliases (derived from identity — avoids .identity.X everywhere)
	localNode  aether.NodeID
	edPriv     ed25519.PrivateKey
	edPub      ed25519.PublicKey
	staticPriv []byte
	staticPub  []byte

	// Handshake + transport config
	partitionKeyResolver PartitionKeyResolver
	handshake            time.Duration
	maxPacket            int
	listenAddr           string

	// NAT/STUN: stun is nil when the transport runs none (NoiseTransportConfig.STUN);
	// stunTx holds a waiter per binding transaction sent on the listener socket.
	stun     aether.STUNClient
	stunTx   map[[12]byte]chan stunResult
	stunMu   sync.Mutex
	stunConn *net.UDPConn

	// Relay
	relayConfig  relay.RelayConfig
	relayService *relay.RelayService
	scopeLimiter *PartitionRelayLimiter

	// Rate limiting
	rateLimiter *tokenBucket   // Global handshake budget
	sourceLimit *sourceLimiter // Per-source-IP budget, checked before any handshake crypto

	// Source validation — issues stateless retry tokens to first-contact
	// addresses when requireRetryToken is true.
	retryGuard        *retryGuard
	requireRetryToken bool

	// Sessions: every session, accepted or dialled, is in the listener's
	// session map (handleHandshake, handleRelayedHandshake,
	// handleResumePacket, registerDialSession and Dial's resume path all Put
	// there), which resolveRelayTarget and findNoiseSession read.
	listener   *noiseListener
	listenerMu sync.Mutex

	// Platform + tuning
	bindResolver     aether.BindAddressResolver
	udpReadBuffer    int
	udpWriteBuffer   int
	nonceWindow      int
	healthAlpha      float64
	inboxSize        int
	ticketStore      *TicketStore
	initiatorTickets *initiatorTicketCache // initiator-side resume cache
	seenTickets      *seenTicketCache      // responder-side replay guard

	// nodeInfoOnce, nodeInfoBytes and nodeInfoErr memoise the signed NodeInfo
	// handshake payload encodeNodeInfo returns. Every input to it (the identity
	// key, the capability bits, initialMaxAckDelayUS, wireVersions) is fixed
	// when NewNoiseTransport returns, so the ed25519.Sign and json.Marshal run
	// once. handleHandshake and handleRelayedHandshake call encodeNodeInfo
	// under the listener-wide l.mu on the read-loop goroutine, where a sign
	// and marshal per inbound msg1 would hold every other datagram of the
	// socket.
	nodeInfoOnce  sync.Once
	nodeInfoBytes []byte
	nodeInfoErr   error

	// wireVersions is the offer every handshake and resume check of this
	// transport uses: aether's entries plus NoiseTransportConfig.WireVersions,
	// fixed at construction, which is what lets encodeNodeInfo memoise the
	// NodeInfo that carries it.
	wireVersions aether.WireVersions

	// Cross-origin anycast forwarder — the intra-origin noise-UDP hairpin
	// in inner_relay.go, read by listener_forward.go on every inbound
	// datagram and reply write. Nil = transport runs in non-forwarder mode
	// (preambled msg1 for non-local targets is dropped, op=1 / op=2
	// frames are ignored). Set via SetForwarder before the listener
	// starts processing traffic.
	forwarder *IntraOriginForwarder
}

// *NoiseTransport is the server-side connHost for every UDP-path noiseConn.
// The browser DialOverConn path uses a nil connHost instead (dial_conn.go).
// This assertion keeps the two in lockstep: adding a connHost method that
// NoiseTransport does not implement fails the build here, not at a call site.
var _ connHost = (*NoiseTransport)(nil)

// hostNonceWindow implements connHost — the configured explicit-nonce replay
// window size. 0 tells noiseConn.nonceWindowSize to use its default.
func (t *NoiseTransport) hostNonceWindow() int { return t.nonceWindow }

// recordInitiatorResume implements connHost: noiseConn.RecordResumeMaterial
// hands it the inbound material, and it lives here so the decode + cache
// types (resumeMaterial, initiatorTicketCache) stay //go:build !js and never
// enter the browser build.
func (t *NoiseTransport) recordInitiatorResume(remoteNode aether.NodeID, data []byte) {
	if t.initiatorTickets == nil {
		return
	}
	m, err := decodeResumeMaterial(data)
	if err != nil {
		dbgNoise.Printf("resume: decode inbound material failed: %v", err)
		return
	}
	t.initiatorTickets.Store(remoteNode, m)
	dbgNoise.Printf("resume: cached material for %s (%d bytes opaque)", remoteNode.Short(), len(m.Opaque))
}

// SetForwarder installs the intra-origin anycast forwarder. Pass nil to
// disable (default). Safe to call once at startup before Listen; not
// safe to swap a live forwarder out from under a running listener
// without coordinating with in-flight relay flows.
func (t *NoiseTransport) SetForwarder(f *IntraOriginForwarder) {
	t.forwarder = f
}

// Forwarder returns the installed forwarder, or nil. Tests use this.
func (t *NoiseTransport) Forwarder() *IntraOriginForwarder {
	return t.forwarder
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

	wireVersions, err := aether.LocalWireVersions(cfg.WireVersions)
	if err != nil {
		return nil, fmt.Errorf("vl1: wire versions: %w", err)
	}

	// --- Config defaults ---
	handshake := cfg.HandshakeTimeout
	if handshake == 0 {
		handshake = noiseDefaultHandshake
	}
	maxPacket := cfg.MaxPacketSize
	if maxPacket <= 0 {
		maxPacket = noiseDefaultMaxPacket
	}
	stunClient := cfg.STUN
	if stunClient == nil && cfg.STUNConfig.Enabled {
		if stunClient, err = aether.NewSTUNClient(cfg.STUNConfig); err != nil {
			return nil, fmt.Errorf("vl1: %w", err)
		}
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
		partitionKeyResolver: cfg.PartitionKeyResolver,
		handshake:            handshake,
		maxPacket:            maxPacket,
		listenAddr:           cfg.ListenAddr,

		// NAT/STUN
		stun:   stunClient,
		stunTx: make(map[[12]byte]chan stunResult),

		// Relay
		relayConfig:  cfg.RelayConfig,
		scopeLimiter: NewPartitionRelayLimiter(cfg.ScopeLimiterConfig),

		// Rate limiting — global + per-source
		rateLimiter: newTokenBucket(float64(rateLimitBurst), float64(rateLimitRate), time.Second),
		sourceLimit: newSourceLimiter(SourceLimitDefaultBurst, SourceLimitDefaultRate, SourceLimitMaxEntries),

		// Source-validation cookies — guard always exists so peers
		// can opt in by sending cookies; enforcement gated on the flag.
		// Tri-state nil → default (on); explicit *false disables it for an
		// initiator that does not read the retry prefix.
		retryGuard:        newRetryGuard(),
		requireRetryToken: resolveRetryTokenDefault(cfg.RequireRetryToken),

		// Platform + tuning
		bindResolver:   cfg.BindResolver,
		udpReadBuffer:  udpReadBuf,
		udpWriteBuffer: udpWriteBuf,
		nonceWindow:    nonceWin,
		healthAlpha:    healthAlpha,
		inboxSize:      inboxSize,
		wireVersions:   wireVersions,
	}

	// Initialize relay service (external session management + forwarding).
	// SessionIndex is set to t itself after construction — NoiseTransport implements
	// relay.SessionIndex via LookupByNodeID and LookupExternal.
	t.relayService = relay.NewRelayService(cfg.RelayConfig, nil)
	t.relayService.SetSessionIndex(t)

	// 0.5-RTT resumption is opt-in. While cfg.EnableResume is false (the
	// default) ticketStore, initiatorTickets and seenTickets stay nil, so
	// tryResumeDial (Dial), the responder's ticket issuance (handleHandshake)
	// and the 0xFA resume packet path (handleResumePacket) all short-circuit;
	// NoiseTransportConfig.EnableResume states what the path does to the
	// shared listener socket.
	// TODO: route the resume path through the listener demux.
	if cfg.EnableResume {
		if ticketStore, ticketErr := NewTicketStore(); ticketErr == nil {
			t.ticketStore = ticketStore
		}
		// Initiator-side resume cache and responder-side replay guard.
		// Kept independent of the ticket key store — these are in-memory
		// only and have no cryptographic secrets.
		t.initiatorTickets = newInitiatorTicketCache(DefaultTicketCacheSize)
		t.seenTickets = newSeenTicketCache(DefaultSeenTicketCacheSize)
	}
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
		WireVersions:     cfg.WireVersions,
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

	// Cross-origin dials prepend a routing preamble so the anycast-receiving
	// machine (M_r) can forward to the target machine (M_t) over 6PN.
	// Caller opts in via target.Metadata[MetadataKeyCrossOriginPreamble]="1";
	// without it, this is a no-op and the dial behaves identically to a
	// direct same-origin or public dial.
	crossOriginPreamble := target.Metadata != nil && target.Metadata[MetadataKeyCrossOriginPreamble] == "1"

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
			return aether.NewConnection(t.localNode, target.NodeID, nc, aether.ProtoNoise), nil
		}
		// Any error (rejected, timeout, tag mismatch) → fall through.
		// tryResumeDial evicts the cache entry on explicit reject so we
		// don't loop attempting a dead ticket.
	}

	session, err := t.performInitiatorHandshakeShared(ctx, listener, addr, path, crossOriginPreamble)
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
		closed:     make(chan struct{}),
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

// punchProbePayload is the body of a hole-punch probe datagram. It is
// deliberately not a valid STUN message, Noise handshake, or QUIC packet
// — a peer's listener classifies an unrecognised datagram as scan
// traffic and drops it, exactly as intended. The bytes only need to
// traverse the path so the sender's NAT/firewall installs an outbound
// mapping for the destination.
var punchProbePayload = []byte("AETHER-PUNCH")

const (
	// punchProbeCount is how many probe datagrams a single PunchProbe
	// sends to one address — a small burst absorbs UDP loss without
	// flooding the path.
	punchProbeCount = 5
	// punchProbeSpacing is the gap between probe datagrams.
	punchProbeSpacing = 50 * time.Millisecond
)

// PunchProbe pre-warms this node's NAT/firewall mapping toward addr by
// sending a short burst of small datagrams from the live listening UDP
// socket — the same socket a peer dialing this node lands on. It is the
// responder half of a coordinated hole-punch: at the agreed T0 the
// initiator dials this node while this node probes the initiator, so
// both NATs install an outbound mapping for the other side at once and
// the initiator's inbound handshake passes the filter.
//
// PunchProbe never reads — it only opens the mapping. The actual Noise
// handshake arrives on the initiator's dial and is accepted by the
// normal listener path. The probe socket is chosen by address family so
// the mapping opened matches the family the peer will dial.
//
// Returns an error if the transport is not listening or every probe
// write fails; a partial burst (some writes succeeded) is treated as
// success — one datagram through is enough to open the mapping.
func (t *NoiseTransport) PunchProbe(ctx context.Context, addr *net.UDPAddr) error {
	if addr == nil {
		return errors.New("noise: PunchProbe nil address")
	}
	t.listenerMu.Lock()
	l := t.listener
	t.listenerMu.Unlock()
	if l == nil {
		return errors.New("noise: PunchProbe before Listen")
	}

	conn := l.conn
	if addr.IP != nil && addr.IP.To4() == nil && l.ipv6Conn != nil {
		conn = l.ipv6Conn // IPv6 destination — probe from the IPv6 socket
	}
	if conn == nil {
		return errors.New("noise: PunchProbe no listening socket")
	}

	var sent int
	var lastErr error
	for i := 0; i < punchProbeCount; i++ {
		if _, err := conn.WriteToUDP(punchProbePayload, addr); err != nil {
			lastErr = err
		} else {
			sent++
		}
		if i == punchProbeCount-1 {
			break
		}
		select {
		case <-ctx.Done():
			if sent > 0 {
				return nil
			}
			return ctx.Err()
		case <-time.After(punchProbeSpacing):
		}
	}
	if sent == 0 {
		return fmt.Errorf("noise: PunchProbe to %s: all writes failed: %w", addr, lastErr)
	}
	return nil
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

// Close releases transport-owned resources. The listener socket lifetime is
// owned by the listener (not the transport), so this only tears down the
// cross-origin forwarder if one was attached — stopping its sweeper goroutine.
func (t *NoiseTransport) Close() error {
	if t.forwarder != nil {
		t.forwarder.Close()
	}
	// Stop the per-source TTL sweeper goroutine so transport
	// teardown doesn't leak it. Stop() is idempotent.
	if t.sourceLimit != nil {
		t.sourceLimit.Stop()
	}
	return nil
}

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
	return aether.NewConnection(t.localNode, id, nc, aether.ProtoNoise)
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

// stunResult is what handleSTUNPacket hands the waiter of a binding transaction:
// the reflexive address the response carries, or why it carries none.
type stunResult struct {
	addr *aether.ReflexiveAddress
	err  error
}

func (t *NoiseTransport) discoverReflexiveAddrMultiplexed(ctx context.Context) (*aether.ReflexiveAddress, error) {
	// Create STUN message
	txID, raw := t.stun.BindingRequest()

	// Register transaction
	ch := make(chan stunResult, 1)
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
		_, _ = t.stunConn.WriteToUDP(raw, serverAddr)
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-ch:
		return resp.addr, resp.err
	case <-time.After(5 * time.Second):
		return nil, errors.New("vl1: STUN timeout")
	}
}

// handleSTUNPacket processes an incoming STUN packet: the response to a binding
// transaction discoverReflexiveAddrMultiplexed waits on goes to its waiter. A
// transport with no STUN client sent no request, and reads none.
func (t *NoiseTransport) handleSTUNPacket(data []byte) {
	if t.stun == nil {
		return
	}
	txID, addr, err := t.stun.BindingResponse(data)
	if err != nil && txID == ([12]byte{}) {
		return
	}

	t.stunMu.Lock()
	ch, ok := t.stunTx[txID]
	t.stunMu.Unlock()

	if ok {
		select {
		case ch <- stunResult{addr: addr, err: err}:
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

// GetSTUNClient returns the transport's STUN client, nil when it runs no STUN. A
// traversing host hands it to nat.StrategyConfig.STUN and reads DetectNATBehaviour
// and DiscoverReflexiveAddr from it.
func (t *NoiseTransport) GetSTUNClient() aether.STUNClient {
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
