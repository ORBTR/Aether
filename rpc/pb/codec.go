/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package pb

import (
	"encoding/binary"
	"errors"
	"io"

	"google.golang.org/protobuf/proto"
)

var (
	ErrMessageTooLarge = errors.New("message exceeds maximum size")
	ErrInvalidMessage  = errors.New("invalid message format")
)

const (
	// MaxMessageSize is the maximum allowed RPC message size (10 MB).
	MaxMessageSize = 10 * 1024 * 1024

	// MaxRPCHops is the maximum number of forwarding hops before an RPC is rejected.
	MaxRPCHops = 6
)

// MarshalRequest serializes an RPCRequest to protobuf bytes.
func MarshalRequest(r *RPCRequest) ([]byte, error) {
	return proto.Marshal(r)
}

// UnmarshalRequest deserializes an RPCRequest from protobuf bytes.
func UnmarshalRequest(data []byte) (*RPCRequest, error) {
	r := &RPCRequest{}
	if err := proto.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

// MarshalResponse serializes an RPCResponse to protobuf bytes.
func MarshalResponse(r *RPCResponse) ([]byte, error) {
	return proto.Marshal(r)
}

// UnmarshalResponse deserializes an RPCResponse from protobuf bytes.
func UnmarshalResponse(data []byte) (*RPCResponse, error) {
	r := &RPCResponse{}
	if err := proto.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

// ReadMessage reads a length-prefixed binary message from the reader.
// Wire format: [4-byte length (BigEndian)][protobuf message]
func ReadMessage(reader io.Reader, maxSize uint32) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > maxSize {
		return nil, ErrMessageTooLarge
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteMessage writes a length-prefixed binary message to the writer.
// Wire format: [4-byte length (BigEndian)][protobuf message]
func WriteMessage(writer io.Writer, data []byte) error {
	length := uint32(len(data))
	if err := binary.Write(writer, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}
