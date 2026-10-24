// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

package tpt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type vectorFile struct {
	Vectors []struct {
		Name       string `json:"name"`
		Seq        uint32 `json:"seq"`
		PayloadHex string `json:"payload_hex"`
		WireHex    string `json:"wire_hex"`
	} `json:"vectors"`
}

// loadVectors reads the vectors the Rust crate also tests against.
func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestCRC32CheckValue(t *testing.T) {
	if got := CRC32([]byte("123456789")); got != 0xCBF43926 {
		t.Fatalf("CRC32 check value: got %#x", got)
	}
}

func TestEncodeMatchesGoldenVectors(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			wire, err := Encode(v.Seq, mustHex(t, v.PayloadHex))
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(wire, mustHex(t, v.WireHex)) {
				t.Fatalf("wire mismatch:\n got  %x\n want %s", wire, v.WireHex)
			}
		})
	}
}

func TestDecodeReturnsGoldenVectors(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			wire := mustHex(t, v.WireHex)
			f, used, err := Decode(wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if f.Seq != v.Seq || !bytes.Equal(f.Payload, mustHex(t, v.PayloadHex)) {
				t.Fatalf("decoded %+v", f)
			}
			if used != len(wire) {
				t.Fatalf("used %d of %d bytes", used, len(wire))
			}
		})
	}
}

func TestEverySingleBitFlipIsDetected(t *testing.T) {
	wire, _ := Encode(9, []byte("reflex"))
	for i := range wire {
		for bit := 0; bit < 8; bit++ {
			bad := append([]byte(nil), wire...)
			bad[i] ^= 1 << bit
			if _, _, err := Decode(bad); err == nil {
				t.Fatalf("flip at byte %d bit %d went undetected", i, bit)
			}
		}
	}
}

func TestEveryPrefixIsRejected(t *testing.T) {
	wire, _ := Encode(3, []byte("abc"))
	for cut := 0; cut < len(wire); cut++ {
		if _, _, err := Decode(wire[:cut]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut at %d: want ErrTruncated, got %v", cut, err)
		}
	}
}

func TestBadVersionAndOversizeAreRejected(t *testing.T) {
	wire, _ := Encode(0, nil)
	wire[0] = 2
	if _, _, err := Decode(wire); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("version: %v", err)
	}
	if _, err := Encode(0, make([]byte, MaxPayloadLen+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize encode: %v", err)
	}
	big := []byte{Version, 0, 0, 0, 0, 0xFF, 0xFF}
	if _, _, err := Decode(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize decode: %v", err)
	}
}

func TestBackToBackFramesDecodeInTurn(t *testing.T) {
	a, _ := Encode(1, []byte("first"))
	b, _ := Encode(2, []byte("second"))
	buf := append(append([]byte(nil), a...), b...)
	f1, used, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	f2, _, err := Decode(buf[used:])
	if err != nil {
		t.Fatal(err)
	}
	if f1.Seq != 1 || string(f1.Payload) != "first" || f2.Seq != 2 || string(f2.Payload) != "second" {
		t.Fatalf("got %+v and %+v", f1, f2)
	}
}
