// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Sends a link frame much larger than one CAN frame over an in-memory bus. It
//! needs no hardware. For a real Linux bus, build `SocketCanBus` (feature
//! `can-socketcan`) in place of the `VirtualBus` nodes.
//!
//! Run with `cargo run --example can_fragment`.

use tpt_link::Link;
use tpt_link::can::{CLASSIC_MTU, CanTransport, VirtualBus};

fn main() {
    let bus = VirtualBus::new();
    let a = CanTransport::new(bus.attach(), 1, CLASSIC_MTU, 1_000_000).expect("node 1");
    let b = CanTransport::new(bus.attach(), 2, CLASSIC_MTU, 1_000_000).expect("node 2");
    let mut sender = Link::new(a);
    let mut receiver = Link::new(b);

    let message = vec![0x42; 600];
    sender.send(&message).expect("send");
    // 600 bytes plus the frame header and CRC, 5 data bytes per CAN frame.
    let got = receiver.poll().expect("poll");
    println!(
        "received {} payload(s), first is {} bytes",
        got.len(),
        got[0].len()
    );
    assert_eq!(got, vec![message]);
}
