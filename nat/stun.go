//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/pion/stun"
)

// Type definitions (aether.NATType, aether.ReflexiveAddress, aether.STUNConfig, DefaultSTUNConfig) are in parent package transport

// STUNClient handles NAT detection and reflexive address discovery
type STUNClient struct {
	config aether.STUNConfig
	mu     sync.RWMutex
	cache  map[string]*aether.ReflexiveAddress // keyed by local address
}

// NewSTUNClient creates a new STUN client with the given configuration
func NewSTUNClient(config aether.STUNConfig) *STUNClient {
	if len(config.Servers) == 0 {
		config.Servers = aether.DefaultSTUNConfig().Servers
	}
	if config.Timeout == 0 {
		config.Timeout = aether.DefaultSTUNConfig().Timeout
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = aether.DefaultSTUNConfig().CacheTTL
	}

	return &STUNClient{
		config: config,
		cache:  make(map[string]*aether.ReflexiveAddress),
	}
}

// Config returns the client configuration
func (c *STUNClient) Config() aether.STUNConfig {
	return c.config
}

// DiscoverReflexiveAddr discovers the public IP:port mapping for a local address
func (c *STUNClient) DiscoverReflexiveAddr(ctx context.Context, localAddr *net.UDPAddr) (*aether.ReflexiveAddress, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("stun: STUN disabled")
	}
	if localAddr == nil {
		return nil, fmt.Errorf("stun: no local address (transport not bound)")
	}

	// Check cache first
	c.mu.RLock()
	cacheKey := localAddr.String()
	if cached, ok := c.cache[cacheKey]; ok {
		age := time.Since(cached.Discovered)
		if age < c.config.CacheTTL {
			c.mu.RUnlock()
			return cached, nil
		}
	}
	c.mu.RUnlock()

	// Try each STUN server in sequence until one succeeds
	var lastErr error
	for _, server := range c.config.Servers {
		result, err := c.querySTUNServer(ctx, localAddr, server)
		if err != nil {
			lastErr = err
			continue
		}

		// Cache successful result
		c.mu.Lock()
		c.cache[cacheKey] = result
		c.mu.Unlock()

		return result, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("stun: all servers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("stun: no servers configured")
}

// querySTUNServer sends a STUN binding request to a specific server
func (c *STUNClient) querySTUNServer(ctx context.Context, localAddr *net.UDPAddr, serverAddr string) (*aether.ReflexiveAddress, error) {
	// Resolve STUN server address
	stunAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server: %w", err)
	}

	// Create UDP connection bound to local address
	conn, err := net.DialUDP("udp", localAddr, stunAddr)
	if err != nil {
		return nil, fmt.Errorf("dial STUN server: %w", err)
	}
	defer conn.Close()

	// Set timeout
	deadline := time.Now().Add(c.config.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Build STUN binding request
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Send request
	if _, err := conn.Write(message.Raw); err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	// Read response
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	// Parse response
	var msg stun.Message
	msg.Raw = buf[:n]
	if err := msg.Decode(); err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	// AE-L-08: verify the response before trusting the mapped address.
	// XORMappedAddress.GetFrom de-XORs using whatever TransactionID the response
	// carries, so a well-formed forged reply is otherwise self-consistent and
	// would poison the reflexive-address cache (see DiscoverReflexiveAddr). The
	// connected UDP socket only filters by source IP:port; the mandatory STUN
	// transaction-ID match (RFC 5389 s7.3.1) and success-class check are the real
	// defenses. `message` is the binding request built at the top of this function.
	if msg.Type != stun.BindingSuccess {
		return nil, fmt.Errorf("stun: unexpected response type %s (want binding success)", msg.Type)
	}
	if msg.TransactionID != message.TransactionID {
		return nil, fmt.Errorf("stun: transaction ID mismatch (possible spoofed response)")
	}

	// Extract XOR-MAPPED-ADDRESS
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(&msg); err != nil {
		return nil, fmt.Errorf("extract XOR-MAPPED-ADDRESS: %w", err)
	}

	// Convert to net.UDPAddr
	publicAddr := &net.UDPAddr{
		IP:   xorAddr.IP,
		Port: xorAddr.Port,
	}

	return &aether.ReflexiveAddress{
		IP:         publicAddr.IP,
		Port:       publicAddr.Port,
		LocalAddr:  localAddr,
		NATType:    c.detectNATType(localAddr, publicAddr),
		Discovered: time.Now(),
		TTL:        c.config.CacheTTL,
	}, nil
}

// detectNATType performs basic NAT type detection based on address comparison
func (c *STUNClient) detectNATType(localAddr, publicAddr *net.UDPAddr) aether.NATType {
	if publicAddr == nil || localAddr == nil {
		return aether.NATUnknown
	}
	// If public IP matches local IP, we have no NAT (open/direct)
	if publicAddr.IP.Equal(localAddr.IP) {
		return aether.NATOpen
	}

	// AE-P-18: a single STUN query reveals only this server's reflexive
	// mapping — it cannot distinguish full-cone / restricted / port-restricted
	// / symmetric behaviour. Asserting NATFullCone here fabricated a confident
	// and frequently-wrong classification (e.g. a symmetric NAT reported as
	// full-cone), which then leaks to external peers via ReflexiveAddress.NATType
	// (NoiseTransport.DiscoverReflexiveAddr) and to DetectNATType's single-server
	// branch. Return NATUnknown so callers fall through to the multi-server
	// DetectNATType / RFC 5780 DetectNATBehaviour paths instead of trusting a
	// guess. Routing is unchanged and no capability is lost — relay/fallback.go
	// chooseStrategy maps both NATUnknown and NATFullCone to StrategyHolePunch
	// (hole-punch then automatic relay fallback) — the fix only stops emitting a
	// false full-cone signal for a NAT we could not actually classify.
	return aether.NATUnknown
}

// DetectNATType performs comprehensive NAT type detection using multiple STUN servers
// This is more thorough than the basic detection in DiscoverReflexiveAddr
func (c *STUNClient) DetectNATType(ctx context.Context, localAddr *net.UDPAddr) (aether.NATType, error) {
	if !c.config.Enabled {
		return aether.NATUnknown, fmt.Errorf("stun: STUN disabled")
	}

	if len(c.config.Servers) < 2 {
		// Need at least 2 STUN servers for full NAT detection
		reflex, err := c.DiscoverReflexiveAddr(ctx, localAddr)
		if err != nil {
			return aether.NATUnknown, err
		}
		return reflex.NATType, nil
	}

	// Query first STUN server
	result1, err := c.querySTUNServer(ctx, localAddr, c.config.Servers[0])
	if err != nil {
		return aether.NATUnknown, fmt.Errorf("query first STUN server: %w", err)
	}

	// Query second STUN server
	result2, err := c.querySTUNServer(ctx, localAddr, c.config.Servers[1])
	if err != nil {
		return aether.NATUnknown, fmt.Errorf("query second STUN server: %w", err)
	}

	// Compare results
	if result1.IP.Equal(localAddr.IP) {
		// Public IP matches local IP - no NAT
		return aether.NATOpen, nil
	}

	// Construct full addresses for comparison
	addr1 := net.JoinHostPort(result1.IP.String(), fmt.Sprintf("%d", result1.Port))
	addr2 := net.JoinHostPort(result2.IP.String(), fmt.Sprintf("%d", result2.Port))

	if addr1 == addr2 {
		// Same external IP:port for different destinations - Full Cone NAT
		return aether.NATFullCone, nil
	}

	// Different external ports for different destinations - Symmetric NAT
	// (This is a simplified check; full detection would need more servers)
	return aether.NATSymmetric, nil
}

// ClearCache removes all cached reflexive addresses
func (c *STUNClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*aether.ReflexiveAddress)
}

// GetCachedAddr retrieves a cached reflexive address if available
func (c *STUNClient) GetCachedAddr(localAddr *net.UDPAddr) *aether.ReflexiveAddress {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cacheKey := localAddr.String()
	if cached, ok := c.cache[cacheKey]; ok {
		age := time.Since(cached.Discovered)
		if age < c.config.CacheTTL {
			return cached
		}
		// Expired, will be removed on next discovery
	}
	return nil
}
