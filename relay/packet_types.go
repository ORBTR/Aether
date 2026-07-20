/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * Packet-type constants — build-tag agnostic (bare integer literals) so the
 * noise package's agnostic noiseConn can reference relay.PacketType* under
 * GOOS=js (browser DialOverConn path) without pulling in the //go:build !js
 * relay service. The remaining relay constants (header/ticket sizing) stay in
 * relay.go with the !js service that uses them.
 */
package relay

const (
	// Packet types (matching PROTOCOLS.md)
	PacketTypeData         = 0x01
	PacketTypePing         = 0x02 // Health check ping
	PacketTypePong         = 0x03 // Health check pong response
	PacketTypeRekey        = 0x04 // Cipher state rekey signal
	PacketTypeResume       = 0x05 // Session ticket resumption
	PacketTypeResumeAck    = 0x06 // Resumption acknowledgment
	PacketTypeRelayRequest = 0x07
	PacketTypeRelayData    = 0x08
)
