//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// MDNSServiceType is the mDNS service type for mesh discovery.
const MDNSServiceType = "_orbtr-mesh._tcp.local."

// Bounds on the discovered-peer map. Without them an on-LAN attacker minting
// fresh nodeIDs (each hitting the trust-on-first-use store branch in
// processMDNSResponse) could grow d.discovered without bound. AE-M-09.
const (
	mdnsPeerTTL       = 10 * time.Minute // forget peers not re-announced within this window
	mdnsMaxDiscovered = 4096             // hard cap on retained peers; oldest evicted first
)

// MDNSPeer represents a peer discovered via mDNS.
type MDNSPeer struct {
	NodeID       string
	Addresses    []string
	Signature    []byte    // ed25519 signature over NodeID + signed (addr=) addresses; Addresses may also carry an unsigned transport-observed dial hint (AE-P-15)
	DiscoveredAt time.Time
}

// MDNSAnnouncement is the data advertised via mDNS TXT records.
type MDNSAnnouncement struct {
	NodeID    string   `json:"nodeId"`
	Addresses []string `json:"addresses"`
	Signature []byte   `json:"signature"` // ed25519 over "MDNS:v1:<nodeID>:<addrs>"
}

// mdnsSignaturePayload builds the canonical byte string for mDNS signatures.
func mdnsSignaturePayload(nodeID string, addresses []string) []byte {
	msg := fmt.Sprintf("MDNS:v1:%s:%s", nodeID, strings.Join(addresses, ","))
	return []byte(msg)
}

// SignMDNSAnnouncement creates a signed mDNS announcement.
func SignMDNSAnnouncement(nodeID string, addresses []string, privateKey ed25519.PrivateKey) MDNSAnnouncement {
	payload := mdnsSignaturePayload(nodeID, addresses)
	sig := ed25519.Sign(privateKey, payload)
	return MDNSAnnouncement{
		NodeID:    nodeID,
		Addresses: addresses,
		Signature: sig,
	}
}

// VerifyMDNSAnnouncement checks the ed25519 signature on an mDNS announcement.
func VerifyMDNSAnnouncement(ann MDNSAnnouncement, publicKey ed25519.PublicKey) bool {
	if len(ann.Signature) == 0 || len(publicKey) == 0 {
		return false
	}
	payload := mdnsSignaturePayload(ann.NodeID, ann.Addresses)
	return ed25519.Verify(publicKey, payload, ann.Signature)
}

// MDNSTransport is the interface for platform-specific mDNS operations.
// This allows the actual mDNS library (e.g., hashicorp/mdns) to be plugged in later
// while keeping the discovery logic testable with stubs.
type MDNSTransport interface {
	// Advertise publishes our presence via mDNS with the given TXT records.
	Advertise(serviceType string, port int, txtRecords []string) error

	// Browse queries for services of the given type and returns raw TXT records
	// from discovered instances.
	Browse(ctx context.Context, serviceType string) ([]MDNSBrowseResult, error)

	// Stop terminates any active advertisements and listeners.
	Stop()
}

// MDNSBrowseResult is a raw mDNS browse response before verification.
type MDNSBrowseResult struct {
	Host       string
	Port       int
	TXTRecords map[string]string // parsed key=value pairs from TXT records
}

// MDNSDiscoverer manages mDNS advertisement and listening for mesh peers.
// It uses the MDNSTransport interface for actual multicast operations,
// allowing stub implementations for testing or environments without multicast.
type MDNSDiscoverer struct {
	mu         sync.RWMutex
	nodeID     string
	addresses  []string
	privateKey ed25519.PrivateKey
	publicKeys func(nodeID string) ed25519.PublicKey // lookup function for peer public keys
	discovered map[string]MDNSPeer                   // nodeID -> peer
	transport  MDNSTransport                         // platform-specific mDNS implementation
	port       int                                   // our mesh port for advertisement
	cancel     context.CancelFunc
	interval   time.Duration // query interval (default: 30s)
}

// MDNSDiscovererOption configures an MDNSDiscoverer.
type MDNSDiscovererOption func(*MDNSDiscoverer)

// WithMDNSTransport sets the platform-specific mDNS aether.
func WithMDNSTransport(t MDNSTransport) MDNSDiscovererOption {
	return func(d *MDNSDiscoverer) { d.transport = t }
}

// WithMDNSQueryInterval sets how often to query for mDNS peers.
func WithMDNSQueryInterval(interval time.Duration) MDNSDiscovererOption {
	return func(d *MDNSDiscoverer) { d.interval = interval }
}

// NewMDNSDiscoverer creates an mDNS discovery instance.
// The publicKeyLookup function is called to verify signatures on discovered peers.
// If transport is nil (no WithMDNSTransport option), mDNS operations are no-ops.
func NewMDNSDiscoverer(
	nodeID string,
	addresses []string,
	port int,
	privateKey ed25519.PrivateKey,
	publicKeyLookup func(nodeID string) ed25519.PublicKey,
	opts ...MDNSDiscovererOption,
) *MDNSDiscoverer {
	d := &MDNSDiscoverer{
		nodeID:     nodeID,
		addresses:  addresses,
		port:       port,
		privateKey: privateKey,
		publicKeys: publicKeyLookup,
		discovered: make(map[string]MDNSPeer),
		interval:   30 * time.Second,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Announce publishes our presence on the local network via mDNS.
// The announcement includes the node ID and an ed25519 signature proving
// ownership of the advertised identity.
func (d *MDNSDiscoverer) Announce(nodeID string, port int) error {
	if d.transport == nil {
		log.Printf("[MDNS] No transport configured, skipping advertisement")
		return nil
	}

	ann := SignMDNSAnnouncement(nodeID, d.addresses, d.privateKey)
	txtRecords := []string{
		"node_id=" + nodeID,
		"sig=" + hex.EncodeToString(ann.Signature),
		"addr=" + strings.Join(d.addresses, ","),
	}

	log.Printf("[MDNS] Advertising %s with %d addresses on port %d",
		MDNSServiceType, len(d.addresses), port)
	return d.transport.Advertise(MDNSServiceType, port, txtRecords)
}

// Start begins mDNS advertisement and periodic peer discovery.
func (d *MDNSDiscoverer) Start(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)

	// Advertise our presence
	if err := d.Announce(d.nodeID, d.port); err != nil {
		log.Printf("[MDNS] Failed to advertise: %v", err)
		// Non-fatal: we can still discover peers even if advertisement fails
	}

	// Periodically query for peers
	go d.listenLoop(ctx)

	return nil
}

// Stop terminates mDNS advertisement and listening.
func (d *MDNSDiscoverer) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.transport != nil {
		d.transport.Stop()
	}
}

// Discover returns all verified peers discovered via mDNS as PeerAddress entries.
// Implements the Discoverer interface.
func (d *MDNSDiscoverer) Discover(_ context.Context) ([]PeerAddress, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]PeerAddress, 0, len(d.discovered))
	for _, p := range d.discovered {
		for _, addr := range p.Addresses {
			host, port := splitHostPort(addr)
			peers = append(peers, PeerAddress{
				Host:   host,
				Port:   port,
				NodeID: p.NodeID,
				Source: "mdns",
			})
		}
	}
	return peers, nil
}

// listenLoop continuously queries for mDNS peers at the configured interval.
func (d *MDNSDiscoverer) listenLoop(ctx context.Context) {
	// Initial query on start
	d.queryPeers(ctx)

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.queryPeers(ctx)
		}
	}
}

// queryPeers performs an mDNS query and processes the results.
func (d *MDNSDiscoverer) queryPeers(ctx context.Context) {
	if d.transport == nil {
		return // no transport, nothing to query
	}

	results, err := d.transport.Browse(ctx, MDNSServiceType)
	if err != nil {
		log.Printf("[MDNS] Browse failed: %v", err)
		return
	}

	for _, r := range results {
		nodeID := r.TXTRecords["node_id"]
		sigHex := r.TXTRecords["sig"]
		addrStr := r.TXTRecords["addr"]

		if nodeID == "" || sigHex == "" {
			continue
		}

		var addresses []string
		if addrStr != "" {
			addresses = strings.Split(addrStr, ",")
		}
		// AE-P-15: the transport-observed host:port is NOT covered by the
		// announcer's ed25519 signature (SignMDNSAnnouncement signs only the
		// addr= set), so it must stay OUT of the address list handed to
		// verification. Appending it here made every genuinely-signed peer fail
		// VerifyMDNSAnnouncement (augmented payload != signed payload) and let a
		// TOFU peer's stored addresses carry an unsigned, attacker-settable
		// endpoint. Pass it separately as an unsigned dial hint instead.
		var observed string
		if r.Host != "" && r.Port > 0 {
			observed = fmt.Sprintf("%s:%d", r.Host, r.Port)
		}

		d.processMDNSResponse(nodeID, addresses, observed, sigHex)
	}
}

// processMDNSResponse validates and stores an mDNS announcement.
func (d *MDNSDiscoverer) processMDNSResponse(nodeID string, addresses []string, observed string, sigHex string) {
	if nodeID == d.nodeID {
		return // ignore our own announcements
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		log.Printf("[MDNS] Invalid signature hex from %s", truncateID(nodeID))
		return
	}

	ann := MDNSAnnouncement{
		NodeID:    nodeID,
		Addresses: addresses,
		Signature: sig,
	}

	if d.publicKeys != nil {
		pubKey := d.publicKeys(nodeID)
		if pubKey == nil {
			// Trust-on-first-use: store but log as unverified
			log.Printf("[MDNS] No public key for %s, storing as unverified", truncateID(nodeID))
		} else if !VerifyMDNSAnnouncement(ann, pubKey) {
			log.Printf("[MDNS] Invalid signature for %s, discarding", truncateID(nodeID))
			return
		}
	}

	// AE-P-15: verification above ran over the signed addr= set only. Add the
	// transport-observed address (if any) as an ADDITIONAL, unsigned dial
	// candidate, de-duplicated against the signed set. It never participated in
	// the signature check, so it can neither break verification nor be laundered
	// as a signed address; preserves the original host:port dial-hint capability.
	stored := addresses
	if observed != "" {
		dup := false
		for _, a := range stored {
			if a == observed {
				dup = true
				break
			}
		}
		if !dup {
			stored = append(append([]string(nil), stored...), observed)
		}
	}

	now := time.Now()
	d.mu.Lock()
	// AE-M-09: bound the discovered-peer map. An on-LAN attacker can mint
	// unlimited distinct nodeIDs — each reaching the trust-on-first-use
	// store-unverified branch above — so without pruning and a hard size cap
	// d.discovered would grow without bound (LAN memory-exhaustion DoS), and
	// every Discover() call allocates an O(len(discovered)) slice. Only enforce
	// the bound when inserting a NEW nodeID; re-announcements of a known peer
	// just refresh it in place.
	if _, exists := d.discovered[nodeID]; !exists {
		// Prune peers not re-announced within the TTL.
		for id, p := range d.discovered {
			if now.Sub(p.DiscoveredAt) > mdnsPeerTTL {
				delete(d.discovered, id)
			}
		}
		// If still at the cap, evict the least-recently-announced peer (FIFO).
		if len(d.discovered) >= mdnsMaxDiscovered {
			var oldestID string
			var oldestAt time.Time
			for id, p := range d.discovered {
				if oldestID == "" || p.DiscoveredAt.Before(oldestAt) {
					oldestID, oldestAt = id, p.DiscoveredAt
				}
			}
			if oldestID != "" {
				delete(d.discovered, oldestID)
			}
		}
	}
	d.discovered[nodeID] = MDNSPeer{
		NodeID:       nodeID,
		Addresses:    stored,
		Signature:    sig,
		DiscoveredAt: now,
	}
	d.mu.Unlock()

	dbgMDNS.Printf("Discovered peer %s at %v", truncateID(nodeID), addresses)
}

// truncateID returns the first 12 characters of an ID for log readability.
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
