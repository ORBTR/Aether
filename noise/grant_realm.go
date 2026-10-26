/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Build-tag agnostic: GrantRealm is computed by DialOverConn in the browser
// (GOOS=js) and by AcceptOverConn on the agent.

package noise

import (
	"encoding/binary"
	"errors"
	"fmt"

	transportCrypto "github.com/ORBTR/aether/crypto/identity"
)

// GrantRealm is the mesh realm an over-conn Noise session's grant binds it to:
// the mesh kind device, the grant's partition and the grant's target, and no
// network key generation, because no over-conn peer holds a network key. Both
// ends of the handshake derive it from the signed grant body each holds,
// DialOverConn from DialConnConfig.Ticket and acceptOverConn from the body
// whose signature it verified, through the GrantRealmFn each config carries,
// and set Prologue as the Noise handshake's prologue. Two ends that read
// different partitions or targets out of their grants therefore fail the
// handshake at msg2 and msg3, before any stream exists. ID is the value the
// fragment envelope's realm field carries on such a session
// (adapter.FragmentEnvelope.Realm, through noiseConn.RealmID).
//
// Partition is the grant body's partition field and Target its target node
// field: the io/constellation signaling DialTicketBody fields Partition (JSON
// "scope") and TargetAgentID (JSON "target"). aether reads neither from the
// body; the consumer's GrantRealmFn does.
type GrantRealm struct {
	Partition string
	Target    string
}

// grantRealmMeshKind names the one mesh kind an over-conn session belongs to.
const grantRealmMeshKind = "device"

// grantRealmPrologueLabel opens every over-conn prologue, so the prologue a
// grant realm gives is never the bytes of a network key, which is the mesh
// transport's prologue (performInitiatorHandshakeSharedAttempt, handleHandshake).
const grantRealmPrologueLabel = "aether/over-conn/grant-realm/1"

// ErrGrantRealmIncomplete refuses a GrantRealm with an empty partition or
// target: a grant that names no partition or no target binds a session to no
// realm, and DialOverConn and acceptOverConn run no handshake on it.
var ErrGrantRealmIncomplete = errors.New("noise: grant realm needs a partition and a target")

// maxGrantRealmField bounds each field so its u16 length prefix in Prologue
// never truncates.
const maxGrantRealmField = 0xFFFF

// Prologue returns the Noise prologue for g: the label and a zero byte, then
// the mesh kind, the partition and the target, each behind a big-endian u16
// length, so no two splits of the same bytes into the three fields give one
// prologue.
func (g GrantRealm) Prologue() ([]byte, error) {
	if g.Partition == "" || g.Target == "" {
		return nil, ErrGrantRealmIncomplete
	}
	if len(g.Partition) > maxGrantRealmField || len(g.Target) > maxGrantRealmField {
		return nil, fmt.Errorf("noise: grant realm field longer than %d bytes", maxGrantRealmField)
	}
	fields := []string{grantRealmMeshKind, g.Partition, g.Target}
	n := len(grantRealmPrologueLabel) + 1
	for _, f := range fields {
		n += 2 + len(f)
	}
	out := make([]byte, 0, n)
	out = append(out, grantRealmPrologueLabel...)
	out = append(out, 0)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	return out, nil
}

// ID returns the fingerprint of g's prologue, which is the realm a session
// bound to g carries in its fragment envelopes. It is derived from the
// prologue the way the mesh transport derives a network key id from its own
// (crypto/identity CRC32Hash), so one FragmentEnvelope.Realm field serves a
// device-mesh, an endpoint-mesh and an over-conn session alike.
func (g GrantRealm) ID() (uint32, error) {
	p, err := g.Prologue()
	if err != nil {
		return 0, err
	}
	return transportCrypto.CRC32Hash(p), nil
}

// grantRealmPrologue runs fn on body and returns the prologue and the realm
// binding the handshake takes from the result. DialOverConn and acceptOverConn
// call it with the same function and the same body bytes on their two ends.
func grantRealmPrologue(fn func(body []byte) (GrantRealm, error), body []byte) ([]byte, realmBinding, error) {
	g, err := fn(body)
	if err != nil {
		return nil, realmBinding{}, fmt.Errorf("grant realm: %w", err)
	}
	prologue, err := g.Prologue()
	if err != nil {
		return nil, realmBinding{}, fmt.Errorf("grant realm: %w", err)
	}
	return prologue, realmBinding{id: transportCrypto.CRC32Hash(prologue), bound: true}, nil
}
