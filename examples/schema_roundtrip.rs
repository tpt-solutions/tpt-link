// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Puts a protobuf core message in a link frame and reads it back.
//!
//! Run with `cargo run --example schema_roundtrip --features proto`.

use micropb::{MessageDecode, MessageEncode, PbEncoder};
use tpt_link::schema::v1::Ack;
use tpt_link::{Link, Loopback};

fn main() {
    let (a, b) = Loopback::pair();
    let mut sender = Link::new(a);
    let mut receiver = Link::new(b);

    let ack = Ack { seq: 42 };
    let mut buf = vec![0u8; Ack::MAX_SIZE.expect("bounded message")];
    ack.encode(&mut PbEncoder::new(&mut buf[..]))
        .expect("encode");
    sender.send(&buf[..ack.compute_size()]).expect("send");

    let payload = receiver.poll().expect("poll").remove(0);
    let mut decoded = Ack::default();
    decoded.decode_from_bytes(&payload).expect("decode");
    println!("received {decoded:?}");
}
