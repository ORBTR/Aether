/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"io"
)

// ReadNextFrame reads one frame from r using the supplied Compressor for
// short-header decoding state, returning either:
//
//   - a single decoded frame (Type=full-header, or one of the short-data /
//     short-control / short-ack / short-encrypted / short-data-var
//     indicators), with batch=nil;
//   - a batch of decoded frames (ShortBatchIndicator), with frame=nil and
//     batch populated;
//   - an error.
//
// The first byte read is also returned as `indicator` so the caller can
// distinguish "short encrypted" (drives nonce stripping) from "full
// header with FlagENCRYPTED" (drives the in-frame nonce path) — those
// are different decrypt entry points so the indicator must flow out
// alongside the frame.
//
// Pre-refactor the Noise and TCP adapters each carried a 50-line copy
// of this decode step. Behaviour is unchanged: indicator dispatch
// matches the Noise + TCP readLoops exactly. Adapters handle their own
// post-decode work (Validate, decrypt, decompress, anti-replay) and
// drive the frame through their own dispatchFrame switch — only the
// raw decode step lives here.
func ReadNextFrame(r io.Reader, c *Compressor) (frame *Frame, indicator byte, batch []*Frame, err error) {
	var buf [1]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return nil, 0, nil, err
	}
	indicator = buf[0]

	if IsShortHeader(indicator) {
		switch indicator {
		case ShortDataIndicator:
			frame, err = c.DecodeDataShort(r)
		case ShortControlIndicator:
			frame, err = c.DecodeControlShort(r)
		case ShortACKIndicator:
			frame, err = c.DecodeACKShort(r)
		case ShortDataVarIndicator:
			frame, err = c.DecodeDataShortVar(r)
		case ShortEncryptedIndicator:
			frame, err = c.DecodeEncryptedDataShort(r)
		case ShortBatchIndicator:
			batch, err = c.DecodeBatch(r)
		default:
			err = fmt.Errorf("aether: unknown short header indicator 0x%02x", indicator)
		}
		return frame, indicator, batch, err
	}

	frame, err = DecodeFrameWithFirstByte(r, indicator)
	if err == nil {
		c.RecordFullHeader(frame)
	}
	return frame, indicator, nil, err
}
