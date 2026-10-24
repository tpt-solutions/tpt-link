// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

package schema

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
)

// The same message encodes to the same bytes in the Rust crate (`schema.rs`
// doc example: Ack { seq: 42 }). Field 1, varint 42, is 08 2a.
func TestAckMatchesRustEncoding(t *testing.T) {
	got, err := proto.Marshal(&Ack{Seq: 42})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x08, 0x2a}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
	var back Ack
	if err := proto.Unmarshal(got, &back); err != nil || back.GetSeq() != 42 {
		t.Fatalf("round trip: %v %+v", err, &back)
	}
}
