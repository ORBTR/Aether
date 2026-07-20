//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Coordinated NAT hole-punching.
//
// Provides the primitives both peers need to coordinate simultaneous
// outbound UDP probes through their respective NATs. The actual
// rendezvous transport (relay, gossip topic, etc.) is the consumer's
// responsibility — this file just defines the signed `PunchRequest`
// and `PunchOffer` payloads.
package nat

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net"

	aether "github.com/ORBTR/aether"
)

// PunchMethod is the strategy a pair of peers should use to punch.
// The strategy engine picks one based on both sides' NATBehaviour.
type PunchMethod uint8

const (
	PunchUnspecified    PunchMethod = iota
	PunchDirect                     // both EIM → simple simultaneous open
	PunchPortPrediction             // one or both APDM → birthday paradox punching
	PunchUPnP                       // try UPnP/NAT-PMP/PCP first
	PunchRelay                      // give up, fall back to a relay
)

func (p PunchMethod) String() string {
	switch p {
	case PunchDirect:
		return "direct"
	case PunchPortPrediction:
		return "port-prediction"
	case PunchUPnP:
		return "upnp"
	case PunchRelay:
		return "relay"
	default:
		return "unspecified"
	}
}

// ChooseMethod selects the punch strategy for the given pair of peers.
// Both EIM → direct simultaneous open (highest success rate).
// Otherwise → port prediction; the strategy engine will substitute
// PunchUPnP when a port mapper is available (cheaper than birthday-style
// fan-out). The previous code returned PunchDirect for asymmetric pairs
// which has the lowest success probability for that case.
func ChooseMethod(local, remote NATBehaviour) PunchMethod {
	if local.Mapping == MappingEndpointIndependent && remote.Mapping == MappingEndpointIndependent {
		return PunchDirect
	}
	// At least one side is symmetric (or unknown). Port prediction is the
	// correct primitive in both the mixed (EIM ↔ APDM) and the both-APDM
	// cases — it's the only single-RTT method that works against APDM.
	return PunchPortPrediction
}

// PunchRequest is the initiator-side proposal to coordinate a punch.
// Carries the initiator's reflexive + local addresses plus a signed
// envelope so the target can verify origin.
type PunchRequest struct {
	RequesterNodeID aether.NodeID
	TargetNodeID    aether.NodeID
	ReflexiveAddrs  []net.UDPAddr
	LocalAddrs      []net.UDPAddr
	Behaviour       NATBehaviour
	Timestamp       int64
	Signature       []byte // Ed25519 over canonical encoding (see SignBytes)
}

// PunchOffer is the responder-side reply, carrying its own addresses +
// behaviour + suggested method. Same signature scheme.
type PunchOffer struct {
	ResponderNodeID aether.NodeID
	RequesterNodeID aether.NodeID
	ReflexiveAddrs  []net.UDPAddr
	LocalAddrs      []net.UDPAddr
	Behaviour       NATBehaviour
	Method          PunchMethod
	Timestamp       int64
	Signature       []byte
}

// ErrPunchSignature is returned when a PunchRequest/Offer signature
// fails Ed25519 verification.
var ErrPunchSignature = errors.New("nat: punch signature invalid")

// appendPunchAddrs folds a candidate-address slice into a signing buffer.
// AE-P-03: the punch signature must cover every ReflexiveAddr/LocalAddr the
// execution layer will send traffic to (execute.go PunchCandidates dials and
// ProbeCandidates probes), otherwise a MITM on the consumer-owned signalling
// channel — which, for the documented relay/gossip rendezvous, is an untrusted
// intermediary — can rewrite the addresses while Verify still passes and
// redirect the probes/dials at attacker-chosen targets. The slice length and
// each address (a length-prefixed canonical 16-byte IP plus a big-endian port)
// are encoded deterministically so Sign and Verify derive identical bytes from
// the same struct fields. Empty/invalid IPs encode as a zero-length IP; ports
// are inherently 16-bit so uint16 truncation is lossless for any dialable port.
func appendPunchAddrs(out []byte, addrs []net.UDPAddr) []byte {
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(addrs)))
	out = append(out, count[:]...)
	for i := range addrs {
		ip := addrs[i].IP.To16() // canonical 16-byte form; nil (len 0) for an empty/invalid IP
		out = append(out, byte(len(ip)))
		out = append(out, ip...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(addrs[i].Port))
		out = append(out, port[:]...)
	}
	return out
}

// SignBytes returns the canonical byte sequence to sign for a request.
// Stable across implementations: requester ‖ target ‖ behaviour ‖ ts ‖ addrs.
func (r *PunchRequest) SignBytes() []byte {
	out := []byte{}
	out = append(out, []byte(r.RequesterNodeID)...)
	out = append(out, 0)
	out = append(out, []byte(r.TargetNodeID)...)
	out = append(out, 0)
	out = append(out, byte(r.Behaviour.Mapping), byte(r.Behaviour.Filtering))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(r.Timestamp))
	out = append(out, ts[:]...)
	// AE-P-03: authenticate the candidate addresses the execution layer acts on.
	out = appendPunchAddrs(out, r.ReflexiveAddrs)
	out = appendPunchAddrs(out, r.LocalAddrs)
	return out
}

// Sign attaches an Ed25519 signature using the requester's private key.
func (r *PunchRequest) Sign(priv ed25519.PrivateKey) {
	r.Signature = ed25519.Sign(priv, r.SignBytes())
}

// Verify checks the signature against the requester's public key.
func (r *PunchRequest) Verify(pub ed25519.PublicKey) error {
	if !ed25519.Verify(pub, r.SignBytes(), r.Signature) {
		return ErrPunchSignature
	}
	return nil
}

// SignBytes / Sign / Verify mirror the request side.
func (o *PunchOffer) SignBytes() []byte {
	out := []byte{}
	out = append(out, []byte(o.ResponderNodeID)...)
	out = append(out, 0)
	out = append(out, []byte(o.RequesterNodeID)...)
	out = append(out, 0)
	out = append(out, byte(o.Behaviour.Mapping), byte(o.Behaviour.Filtering), byte(o.Method))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(o.Timestamp))
	out = append(out, ts[:]...)
	// AE-P-03: authenticate the candidate addresses the execution layer acts on.
	out = appendPunchAddrs(out, o.ReflexiveAddrs)
	out = appendPunchAddrs(out, o.LocalAddrs)
	return out
}

func (o *PunchOffer) Sign(priv ed25519.PrivateKey) {
	o.Signature = ed25519.Sign(priv, o.SignBytes())
}

func (o *PunchOffer) Verify(pub ed25519.PublicKey) error {
	if !ed25519.Verify(pub, o.SignBytes(), o.Signature) {
		return ErrPunchSignature
	}
	return nil
}
