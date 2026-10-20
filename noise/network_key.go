/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"encoding/binary"
	"errors"
)

// errNetworkKeyBindingMalformed refuses an encoded binding that is not one
// encodeNetworkKeyBinding writes. DecryptTicket reports it as
// ErrTicketInvalid and decodeResumeMaterial wraps it.
var errNetworkKeyBindingMalformed = errors.New("vl1: network key binding malformed")

// networkKeyBinding is the network key a conn's handshake bound it to: the
// key's CRC32 fingerprint and whether one was bound at all. noiseConn holds
// it; tickets and resume material carry it so a resumed conn binds the same
// key as the session it resumes.
type networkKeyBinding struct {
	id    uint32
	bound bool
}

// networkKeyBindingSize is the encoded size of a networkKeyBinding: [1-byte
// bound 0 or 1][4-byte big-endian fingerprint, zero when unbound].
const networkKeyBindingSize = 5

func encodeNetworkKeyBinding(k networkKeyBinding) []byte {
	b := make([]byte, networkKeyBindingSize)
	if k.bound {
		b[0] = 1
		binary.BigEndian.PutUint32(b[1:], k.id)
	}
	return b
}

// decodeNetworkKeyBinding reads exactly networkKeyBindingSize bytes, refusing a
// bound byte other than 0 or 1 and an unbound binding with a fingerprint, so
// every accepted encoding is the one encodeNetworkKeyBinding writes.
func decodeNetworkKeyBinding(b []byte) (networkKeyBinding, error) {
	if len(b) != networkKeyBindingSize {
		return networkKeyBinding{}, errNetworkKeyBindingMalformed
	}
	id := binary.BigEndian.Uint32(b[1:])
	switch b[0] {
	case 1:
		return networkKeyBinding{id: id, bound: true}, nil
	case 0:
		if id != 0 {
			return networkKeyBinding{}, errNetworkKeyBindingMalformed
		}
		return networkKeyBinding{}, nil
	default:
		return networkKeyBinding{}, errNetworkKeyBindingMalformed
	}
}
