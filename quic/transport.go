//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// QuicTransportConfig configures the QUIC aether.
type QuicTransportConfig struct {
	LocalNode    aether.NodeID
	PrivateKey   ed25519.PrivateKey
	KeepAlive    time.Duration
	ListenAddr   string
	BindResolver aether.BindAddressResolver // Optional platform bind resolver (for standalone listen)

	// G07: 0-RTT resumption. When enabled, QUIC connections to known peers
	// skip the TLS handshake round-trip using cached session tickets.
	// The TLS ClientSessionCache stores tickets in memory (or SQLite via adapter).
	Allow0RTT          bool                    // Enable 0-RTT early data
	ClientSessionCache tls.ClientSessionCache  // If nil, uses tls.NewLRUClientSessionCache(64)
}

// QuicTransport implements the Transport interface using QUIC.
type QuicTransport struct {
	localNode  aether.NodeID
	privateKey ed25519.PrivateKey
	tlsConfig  *tls.Config
	keepAlive  time.Duration
	listenAddr string
	allow0RTT  bool
	packetConn net.PacketConn    // if set, use this instead of creating a new socket
	sharedTr   *quic.Transport   // reusable quic.Transport for shared PacketConn
	mu         sync.Mutex
}

// SetPacketConn configures an external PacketConn for QUIC to use (UDP port multiplexing).
func (t *QuicTransport) SetPacketConn(conn net.PacketConn) {
	t.packetConn = conn
}

// NewQuicTransport creates a new QUIC aether.
func NewQuicTransport(cfg QuicTransportConfig) (*QuicTransport, error) {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("quic: invalid ed25519 key")
	}

	// Generate TLS config from Ed25519 key
	tlsConfig, err := generateTLSConfig(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}

	// G07: Configure TLS session cache for 0-RTT resumption
	if cfg.Allow0RTT {
		sessionCache := cfg.ClientSessionCache
		if sessionCache == nil {
			sessionCache = tls.NewLRUClientSessionCache(64)
		}
		tlsConfig.ClientSessionCache = sessionCache
	}

	return &QuicTransport{
		localNode:  cfg.LocalNode,
		privateKey: cfg.PrivateKey,
		tlsConfig:  tlsConfig,
		keepAlive:  cfg.KeepAlive,
		listenAddr: cfg.ListenAddr,
		allow0RTT:  cfg.Allow0RTT,
	}, nil
}

// NewQuicTransportFromConfig creates a QUIC transport from the unified Config.
// Returns nil if Config.QUIC is nil (protocol disabled).
func NewQuicTransportFromConfig(cfg aether.Config) (*QuicTransport, error) {
	if cfg.QUIC == nil {
		return nil, nil
	}
	qc := cfg.QUIC
	return NewQuicTransport(QuicTransportConfig{
		LocalNode:  cfg.NodeID,
		PrivateKey: cfg.PrivateKey,
		ListenAddr: qc.ListenAddr,
		KeepAlive:  qc.KeepAlive,
		Allow0RTT:  qc.Allow0RTT,
	})
}

// Dial establishes a QUIC connection to the provided target.
func (t *QuicTransport) Dial(ctx context.Context, target aether.Target) (aether.Connection, error) {
	if target.Address == "" {
		return nil, errors.New("quic: missing address")
	}

	// Dial the QUIC connection
	tlsConf := t.tlsConfig.Clone()
	tlsConf.ServerName = string(target.NodeID)

	quicCfg := &quic.Config{
		KeepAlivePeriod: t.keepAlive,
		Allow0RTT:       t.allow0RTT,
	}

	var conn quic.Connection
	var err error
	if t.packetConn != nil {
		// Use shared packet conn (UDP port multiplexing with Noise).
		// Reuse a single quic.Transport to avoid quic-go's connMultiplexer
		// panicking on duplicate PacketConn registration.
		t.mu.Lock()
		if t.sharedTr == nil {
			t.sharedTr = &quic.Transport{Conn: t.packetConn}
		}
		tr := t.sharedTr
		t.mu.Unlock()

		addr, resolveErr := net.ResolveUDPAddr("udp", target.Address)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if t.allow0RTT {
			// G07: Use DialEarly for 0-RTT — sends data before handshake completes
			earlyConn, dialErr := tr.DialEarly(ctx, addr, tlsConf, quicCfg)
			conn, err = earlyConn, dialErr
		} else {
			conn, err = tr.Dial(ctx, addr, tlsConf, quicCfg)
		}
	} else {
		if t.allow0RTT {
			earlyConn, dialErr := quic.DialAddrEarly(ctx, target.Address, tlsConf, quicCfg)
			conn, err = earlyConn, dialErr
		} else {
			conn, err = quic.DialAddr(ctx, target.Address, tlsConf, quicCfg)
		}
	}
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoQUIC, target.NodeID, err)
	}

	// Create the session
	return NewQuicSession(t.localNode, target.NodeID, conn), nil
}

// Listen starts accepting QUIC connections.
func (t *QuicTransport) Listen(ctx context.Context) (aether.Listener, error) {
	addr := t.listenAddr
	if addr == "" {
		addr = ":0"
	}

	quicListenCfg := &quic.Config{
		KeepAlivePeriod: t.keepAlive,
		Allow0RTT:       t.allow0RTT,
	}
	if t.allow0RTT {
		earlyLn, listenErr := quic.ListenAddrEarly(addr, t.tlsConfig, quicListenCfg)
		if listenErr != nil {
			return nil, aether.WrapOp("listen", aether.ProtoQUIC, "", listenErr)
		}
		return &QuicListener{earlyListener: earlyLn, localNode: t.localNode, early: true}, nil
	}
	listener, err := quic.ListenAddr(addr, t.tlsConfig, quicListenCfg)
	if err != nil {
		return nil, aether.WrapOp("listen", aether.ProtoQUIC, "", err)
	}

	return &QuicListener{
		listener:  listener,
		localNode: t.localNode,
	}, nil
}

// Close shuts down the aether.
func (t *QuicTransport) Close() error {
	return nil
}

// Protocol implements aether.ProtocolAdapter.
func (t *QuicTransport) Protocol() aether.Protocol { return aether.ProtoQUIC }

// Compile-time interface check.
var _ aether.ProtocolAdapter = (*QuicTransport)(nil)

// QuicListener implements aether.Listener for QUIC.
type QuicListener struct {
	listener      *quic.Listener
	earlyListener *quic.EarlyListener // non-nil when 0-RTT enabled
	early         bool
	localNode     aether.NodeID
}

// Accept waits for the next incoming session.
func (l *QuicListener) Accept(ctx context.Context) (aether.Connection, error) {
	var conn quic.Connection
	var err error
	if l.early && l.earlyListener != nil {
		conn, err = l.earlyListener.Accept(ctx)
	} else {
		conn, err = l.listener.Accept(ctx)
	}
	if err != nil {
		return nil, err
	}

	// Extract NodeID from peer certificate
	cs := conn.ConnectionState().TLS
	if len(cs.PeerCertificates) == 0 {
		conn.CloseWithError(0, "no certificate")
		return l.Accept(ctx) // Try next
	}
	pubKey, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		conn.CloseWithError(0, "invalid key type")
		return l.Accept(ctx)
	}
	remoteNodeID, err := aether.NewNodeID(pubKey)
	if err != nil {
		conn.CloseWithError(0, "invalid node id")
		return l.Accept(ctx)
	}

	return NewQuicSession(l.localNode, remoteNodeID, conn), nil
}

// Close stops listening.
func (l *QuicListener) Close() error {
	if l.early && l.earlyListener != nil {
		return l.earlyListener.Close()
	}
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

// Addr returns the local address.
func (l *QuicListener) Addr() net.Addr {
	if l.early && l.earlyListener != nil {
		return l.earlyListener.Addr()
	}
	return l.listener.Addr()
}

// generateTLSConfig creates a TLS config that uses the Ed25519 key.
func generateTLSConfig(key ed25519.PrivateKey) (*tls.Config, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// We need to encode the private key to PEM as well to create a tls.Certificate
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		NextProtos:         []string{"vl1-quic"},
		InsecureSkipVerify: true, // We verify manually in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("vl1: no peer certificate")
			}
			cert := cs.PeerCertificates[0]
			pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("vl1: peer key is not Ed25519")
			}

			peerNodeID, err := aether.NewNodeID(pubKey)
			if err != nil {
				return err
			}

			// If ServerName is set (client side), verify it matches
			if cs.ServerName != "" && cs.ServerName != string(peerNodeID) {
				return errors.New("vl1: peer node ID mismatch")
			}

			return nil
		},
	}, nil
}
