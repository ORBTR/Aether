/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package noise

import (
	"encoding/binary"
	"errors"
)

// errRealmBindingMalformed refuses an encoded binding that is not one
// encodeRealmBinding writes. DecryptTicket reports it as ErrTicketInvalid and
// decodeResumeMaterial wraps it.
var errRealmBindingMalformed = errors.New("vl1: realm binding malformed")

// realmBinding is the mesh realm a conn's handshake bound it to, as the CRC32
// fingerprint (crypto/identity CRC32Hash) of its Noise prologue, and whether
// one was bound at all. On the mesh transport the prologue is the network key
// (performInitiatorHandshakeSharedAttempt, handleHandshake), so the fingerprint is
// the network key id msg1 names; on an over-conn handshake it is the grant
// realm (GrantRealm.Prologue in DialOverConn and acceptOverConn). An over-conn
// conn whose handshake had no grant is unbound. noiseConn holds it and reports
// it through RealmID; tickets and resume material carry it so a resumed conn
// binds the realm of the session it resumes.
type realmBinding struct {
	id    uint32
	bound bool
}

// realmBindingSize is the encoded size of a realmBinding: [1-byte bound 0 or
// 1][4-byte big-endian fingerprint, zero when unbound].
const realmBindingSize = 5

func encodeRealmBinding(k realmBinding) []byte {
	b := make([]byte, realmBindingSize)
	if k.bound {
		b[0] = 1
		binary.BigEndian.PutUint32(b[1:], k.id)
	}
	return b
}

// decodeRealmBinding reads exactly realmBindingSize bytes, refusing a bound
// byte other than 0 or 1 and an unbound binding with a fingerprint, so every
// accepted encoding is the one encodeRealmBinding writes.
func decodeRealmBinding(b []byte) (realmBinding, error) {
	if len(b) != realmBindingSize {
		return realmBinding{}, errRealmBindingMalformed
	}
	id := binary.BigEndian.Uint32(b[1:])
	switch b[0] {
	case 1:
		return realmBinding{id: id, bound: true}, nil
	case 0:
		if id != 0 {
			return realmBinding{}, errRealmBindingMalformed
		}
		return realmBinding{}, nil
	default:
		return realmBinding{}, errRealmBindingMalformed
	}
}
