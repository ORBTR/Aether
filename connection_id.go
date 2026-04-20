package aether

import (
	"crypto/rand"
	"fmt"
)

// ConnectionIDSize is the byte size of a connection identifier.
const ConnectionIDSize = 8

// ConnectionID uniquely identifies a multiplexed session.
// Generated randomly at session creation. Stable across IP changes.
type ConnectionID [ConnectionIDSize]byte

// GenerateConnectionID creates a cryptographically random connection ID.
func GenerateConnectionID() (ConnectionID, error) {
	var id ConnectionID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("generate connection ID: %w", err)
	}
	return id, nil
}

// IsZero returns true if the connection ID is all zeros (uninitialized).
func (c ConnectionID) IsZero() bool {
	return c == ConnectionID{}
}

// String returns the hex representation.
func (c ConnectionID) String() string {
	return fmt.Sprintf("%x", c[:])
}

// Short returns a truncated hex representation for logging.
func (c ConnectionID) Short() string {
	return fmt.Sprintf("%x", c[:4])
}
