// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Package tpt-link's Go wire codec. It implements frame format version 1
// (spec section 3) and matches the Rust crate byte for byte. Golden vectors are
// shared in testdata/vectors.json. Standard library only.
package tpt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	// Version is the only frame version this codec understands.
	Version byte = 1
	// HeaderLen is the version, seq and length fields.
	HeaderLen = 1 + 4 + 2
	// CRCLen is the trailing CRC-32.
	CRCLen = 4
	// MaxPayloadLen is the largest payload a frame may carry.
	MaxPayloadLen = 1024
)

var (
	ErrTruncated  = errors.New("frame is truncated")
	ErrBadVersion = errors.New("unsupported frame version")
	ErrTooLarge   = errors.New("payload exceeds the maximum")
	ErrBadCRC     = errors.New("CRC mismatch")
)

// CRC32 computes the CRC-32 (IEEE 802.3, reflected 0xEDB88320) of data.
// This is the same function the Rust crate uses.
func CRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// Frame is a decoded frame. Payload aliases the buffer it was decoded from.
type Frame struct {
	Seq     uint32
	Payload []byte
}

// Encode returns the wire bytes for one frame.
func Encode(seq uint32, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayloadLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(payload))
	}
	out := make([]byte, HeaderLen+len(payload)+CRCLen)
	out[0] = Version
	binary.LittleEndian.PutUint32(out[1:5], seq)
	binary.LittleEndian.PutUint16(out[5:7], uint16(len(payload)))
	copy(out[HeaderLen:], payload)
	body := HeaderLen + len(payload)
	binary.LittleEndian.PutUint32(out[body:], CRC32(out[:body]))
	return out, nil
}

// Decode reads the frame at the start of buf. It returns the frame and the
// number of bytes it used, so that back-to-back frames can be read in turn.
func Decode(buf []byte) (Frame, int, error) {
	if len(buf) < 1 {
		return Frame{}, 0, ErrTruncated
	}
	if buf[0] != Version {
		return Frame{}, 0, fmt.Errorf("%w: %d", ErrBadVersion, buf[0])
	}
	if len(buf) < HeaderLen {
		return Frame{}, 0, ErrTruncated
	}
	seq := binary.LittleEndian.Uint32(buf[1:5])
	n := int(binary.LittleEndian.Uint16(buf[5:7]))
	if n > MaxPayloadLen {
		return Frame{}, 0, fmt.Errorf("%w: %d bytes", ErrTooLarge, n)
	}
	body := HeaderLen + n
	total := body + CRCLen
	if len(buf) < total {
		return Frame{}, 0, ErrTruncated
	}
	expected := binary.LittleEndian.Uint32(buf[body:total])
	if actual := CRC32(buf[:body]); actual != expected {
		return Frame{}, 0, fmt.Errorf("%w: frame has %#08x, computed %#08x", ErrBadCRC, expected, actual)
	}
	return Frame{Seq: seq, Payload: buf[HeaderLen:body]}, total, nil
}
