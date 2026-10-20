/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"io"
)

// ReadNextFrame reads one frame from r in the grammar c holds, returning
// either:
//
//   - a single decoded frame: a full frame (indicator FullFrameDiscriminator)
//     or one of the short data, control, ACK, encrypted-data and varint-data
//     forms, with batch nil;
//   - the children of a batch (ShortBatchIndicator), with frame nil;
//   - an error.
//
// The first byte is the frame's discriminator and is the only thing that
// decides its form. FullFrameDiscriminator is a full frame. The short forms
// 0x82-0x88 are read only when the session chose WireVersionFrameShort
// (Compressor.UseWireVersions). Any other first byte, and a short form on a
// session without them, is refused with a *FrameDiscriminatorError after
// that one byte is read, so nothing is sliced or allocated for it.
//
// The indicator is returned with the frame because the Noise read loop
// decrypts a short encrypted frame (nonce in the payload) differently from a
// full frame with FlagENCRYPTED (nonce in the header). The Noise and TCP read
// loops call this; each does its own Validate, decrypt, decompress and
// dispatch afterwards. c is the session's decode-side Compressor, whose
// identity a full frame updates for the short forms that follow it.
func ReadNextFrame(r io.Reader, c *Compressor) (frame *Frame, indicator byte, batch []*Frame, err error) {
	var buf [1]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return nil, 0, nil, err
	}
	indicator = buf[0]

	if indicator == FullFrameDiscriminator {
		frame, err = DecodeFrameWithFirstByte(r, indicator)
		if err == nil {
			c.RecordFullHeader(frame)
		}
		return frame, indicator, nil, err
	}

	if !c.ShortForms() {
		return nil, indicator, nil, &FrameDiscriminatorError{Discriminator: indicator}
	}
	switch indicator {
	case ShortDataIndicator:
		frame, err = c.DecodeDataShort(r)
	case ShortControlIndicator:
		frame, err = c.DecodeControlShort(r)
	case ShortACKIndicator:
		frame, err = c.DecodeACKShort(r)
	case ShortACKFullIndicator:
		frame, err = c.DecodeACKShortFull(r)
	case ShortDataVarIndicator:
		frame, err = c.DecodeDataShortVar(r)
	case ShortEncryptedIndicator:
		frame, err = c.DecodeEncryptedDataShort(r)
	case ShortBatchIndicator:
		batch, err = c.DecodeBatch(r)
	default:
		return nil, indicator, nil, &FrameDiscriminatorError{Discriminator: indicator, ShortForms: true}
	}
	return frame, indicator, batch, err
}
