//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/nat"
)

var (
	ErrNoRelaysAvailable = errors.New("relay: no relays available")
	ErrAllDialsFailed    = errors.New("relay: all connection attempts failed")
)

// RelayInfo represents a discovered relay node.
type RelayInfo struct {
	NodeID    [32]byte // Relay node's Ed25519 public key
	Address   string   // Relay's UDP address
	PublicKey ed25519.PublicKey
	Region    string
	Latency   time.Duration
}

// ConnectionStrategy determines how to connect to a peer.
type ConnectionStrategy int

const (
	StrategyDirect    ConnectionStrategy = iota // Direct P2P connection
	StrategyHolePunch                           // UDP hole-punching via STUN
	StrategyRelay                               // Relay through intermediate node
)

// FallbackDialer provides automatic NAT traversal with relay fallback.
// It attempts direct connection, then hole-punching, then relay.
type FallbackDialer struct {
	mu          sync.RWMutex
	stunClient  *nat.STUNClient
	localNodeID [32]byte
	privateKey  ed25519.PrivateKey

	// Cached NAT type detection
	cachedNATType aether.NATType
	natDetectedAt time.Time
	natCacheTTL   time.Duration

	// Relay discovery function (injected from LAD)
	discoverRelays func(ctx context.Context, preferRegion string) ([]RelayInfo, error)

	// Direct dial function (injected from VL1 transport)
	directDial func(ctx context.Context, addr string, nodeID [32]byte) (aether.Connection, error)

	// Connection timeout
	dialTimeout time.Duration

	// Metrics
	directAttempts  int64
	directSuccesses int64
	relayAttempts   int64
	relaySuccesses  int64
}

// FallbackConfig configures the fallback dialer.
type FallbackConfig struct {
	LocalNodeID    [32]byte
	PrivateKey     ed25519.PrivateKey
	STUNConfig     aether.STUNConfig
	NATCacheTTL    time.Duration
	DialTimeout    time.Duration
	DiscoverRelays func(ctx context.Context, preferRegion string) ([]RelayInfo, error)
	DirectDial     func(ctx context.Context, addr string, nodeID [32]byte) (aether.Connection, error)
}

// NewFallbackDialer creates a dialer with automatic relay fallback.
func NewFallbackDialer(cfg FallbackConfig) *FallbackDialer {
	if cfg.NATCacheTTL == 0 {
		cfg.NATCacheTTL = 5 * time.Minute
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	return &FallbackDialer{
		stunClient:     nat.NewSTUNClient(cfg.STUNConfig),
		localNodeID:    cfg.LocalNodeID,
		privateKey:     cfg.PrivateKey,
		cachedNATType:  aether.NATUnknown,
		natCacheTTL:    cfg.NATCacheTTL,
		dialTimeout:    cfg.DialTimeout,
		discoverRelays: cfg.DiscoverRelays,
		directDial:     cfg.DirectDial,
	}
}

// Dial connects to a target, automatically falling back to relay if needed.
// Order of attempts:
// 1. Direct connection (if NAT type permits)
// 2. Relay connection (if direct fails or symmetric NAT detected)
func (d *FallbackDialer) Dial(ctx context.Context, targetAddr string, targetNodeID [32]byte) (aether.Connection, error) {
	// Determine NAT type
	natType, err := d.detectNATType(ctx)
	if err != nil {
		dbgRelay.Printf("NAT detection failed: %v, assuming open NAT", err)
		log.Printf("[Relay Fallback] NAT detection failed: %v, assuming open NAT", err)
		natType = aether.NATOpen
	}

	// Choose strategy based on NAT type
	strategy := d.chooseStrategy(natType)

	switch strategy {
	case StrategyDirect, StrategyHolePunch:
		// Try direct connection first
		session, err := d.tryDirectDial(ctx, targetAddr, targetNodeID)
		if err == nil {
			return session, nil
		}
		dbgRelay.Printf("Direct connection failed: %v, trying relay", err)
		log.Printf("[Relay Fallback] Direct connection failed: %v, trying relay", err)

		// Fall back to relay
		return d.tryRelayDial(ctx, targetAddr, targetNodeID)

	case StrategyRelay:
		// Symmetric NAT detected - go straight to relay
		dbgRelay.Printf("Symmetric NAT detected, using relay")
		log.Printf("[Relay Fallback] Symmetric NAT detected, using relay")
		return d.tryRelayDial(ctx, targetAddr, targetNodeID)
	}

	return nil, ErrAllDialsFailed
}

// detectNATType detects the local NAT type, caching the result.
func (d *FallbackDialer) detectNATType(ctx context.Context) (aether.NATType, error) {
	d.mu.RLock()
	if d.cachedNATType != aether.NATUnknown && time.Since(d.natDetectedAt) < d.natCacheTTL {
		cachedType := d.cachedNATType
		d.mu.RUnlock()
		return cachedType, nil
	}
	d.mu.RUnlock()

	// Create a temporary UDP connection for NAT detection
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return aether.NATUnknown, err
	}

	detectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	natType, err := d.stunClient.DetectNATType(detectCtx, localAddr)
	if err != nil {
		return aether.NATUnknown, err
	}

	// Cache result
	d.mu.Lock()
	d.cachedNATType = natType
	d.natDetectedAt = time.Now()
	d.mu.Unlock()

	dbgRelay.Printf("Detected NAT type: %s", natType)
	log.Printf("[Relay Fallback] Detected NAT type: %s", natType)
	return natType, nil
}

// chooseStrategy selects connection strategy based on NAT type.
func (d *FallbackDialer) chooseStrategy(natType aether.NATType) ConnectionStrategy {
	switch natType {
	case aether.NATSymmetric:
		// Symmetric NAT - direct connection very unlikely to work
		return StrategyRelay
	case aether.NATOpen:
		// No NAT - direct connection
		return StrategyDirect
	default:
		// Other NAT types - try hole-punching first
		return StrategyHolePunch
	}
}

// tryDirectDial attempts a direct P2P connection.
func (d *FallbackDialer) tryDirectDial(ctx context.Context, targetAddr string, targetNodeID [32]byte) (aether.Connection, error) {
	if d.directDial == nil {
		return nil, errors.New("relay: direct dial function not configured")
	}

	d.mu.Lock()
	d.directAttempts++
	d.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, d.dialTimeout)
	defer cancel()

	session, err := d.directDial(dialCtx, targetAddr, targetNodeID)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.directSuccesses++
	d.mu.Unlock()

	return session, nil
}

// tryRelayDial connects through a relay node.
func (d *FallbackDialer) tryRelayDial(ctx context.Context, targetAddr string, targetNodeID [32]byte) (aether.Connection, error) {
	if d.discoverRelays == nil {
		return nil, errors.New("relay: relay discovery function not configured")
	}

	d.mu.Lock()
	d.relayAttempts++
	d.mu.Unlock()

	// Discover available relays
	relays, err := d.discoverRelays(ctx, "")
	if err != nil || len(relays) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrNoRelaysAvailable
	}

	// Try each relay until one succeeds
	var lastErr error
	for _, relay := range relays {
		session, err := d.dialViaRelay(ctx, relay, targetNodeID)
		if err != nil {
			lastErr = err
			dbgRelay.Printf("Relay %s failed: %v", relay.Address, err)
			log.Printf("[Relay Fallback] Relay %s failed: %v", relay.Address, err)
			continue
		}

		d.mu.Lock()
		d.relaySuccesses++
		d.mu.Unlock()

		dbgRelay.Printf("Connected via relay %s", relay.Address)
		log.Printf("[Relay Fallback] Connected via relay %s", relay.Address)
		return session, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoRelaysAvailable
}

// dialViaRelay establishes a relayed connection to the target.
func (d *FallbackDialer) dialViaRelay(ctx context.Context, relay RelayInfo, targetNodeID [32]byte) (aether.Connection, error) {
	// Request a relay ticket from the relay node
	// This would normally involve an RPC call to the relay
	// For now, we use the local private key to create a self-signed ticket
	// In production, the relay would issue the ticket after authorization

	ticket, err := NewRelayTicket(
		d.privateKey,
		d.localNodeID,
		targetNodeID,
		1*time.Hour, // 1 hour validity
	)
	if err != nil {
		return nil, err
	}

	// Connect to relay using direct dial
	if d.directDial == nil {
		return nil, errors.New("relay: direct dial function not configured")
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.dialTimeout)
	defer cancel()

	session, err := d.directDial(dialCtx, relay.Address, relay.NodeID)
	if err != nil {
		return nil, err
	}

	// Wrap session in relay session
	return NewRelayedSession(session, ticket, targetNodeID), nil
}

// Stats returns connection statistics.
func (d *FallbackDialer) Stats() (directAttempts, directSuccesses, relayAttempts, relaySuccesses int64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.directAttempts, d.directSuccesses, d.relayAttempts, d.relaySuccesses
}

// RelayedSession wraps a session that goes through a relay.
type RelayedSession struct {
	underlying aether.Connection
	ticket     *RelayTicket
	targetID   [32]byte
}

// NewRelayedSession creates a new relayed session wrapper.
func NewRelayedSession(underlying aether.Connection, ticket *RelayTicket, targetID [32]byte) *RelayedSession {
	return &RelayedSession{
		underlying: underlying,
		ticket:     ticket,
		targetID:   targetID,
	}
}

// Send wraps data with relay header and sends through relay.
func (s *RelayedSession) Send(ctx context.Context, payload []byte) error {
	// Prepend relay header: [type:1][targetID:32][payload:...]
	relayData := make([]byte, 1+32+len(payload))
	relayData[0] = PacketTypeRelayData
	copy(relayData[1:33], s.targetID[:])
	copy(relayData[33:], payload)

	return s.underlying.Send(ctx, relayData)
}

// Receive reads data from relay and strips relay header.
func (s *RelayedSession) Receive(ctx context.Context) ([]byte, error) {
	data, err := s.underlying.Receive(ctx)
	if err != nil {
		return nil, err
	}

	// Strip relay header
	if len(data) < 33 {
		return nil, ErrInvalidPacket
	}
	if data[0] != PacketTypeRelayData {
		return nil, ErrInvalidPacket
	}

	return data[33:], nil
}

// Close closes the underlying session.
func (s *RelayedSession) Close() error {
	return s.underlying.Close()
}

// RemoteAddr returns the remote address (the relay's address).
func (s *RelayedSession) RemoteAddr() net.Addr {
	return s.underlying.RemoteAddr()
}

// RemoteNodeID returns the actual target node ID (not the relay).
func (s *RelayedSession) RemoteNodeID() aether.NodeID {
	return aether.NodeID(s.targetID[:])
}

// IsRelayed returns true if this is a relayed session.
func (s *RelayedSession) IsRelayed() bool {
	return true
}

// Ticket returns the relay ticket used for this session.
func (s *RelayedSession) Ticket() *RelayTicket {
	return s.ticket
}

func (s *RelayedSession) NetConn() net.Conn { return nil } // Relay doesn't expose raw net.Conn
func (s *RelayedSession) Protocol() aether.Protocol { return aether.ProtoUnknown }
func (s *RelayedSession) OnClose(fn func()) { /* Relay handles lifecycle */ }
