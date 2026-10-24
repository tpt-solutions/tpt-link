// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Shows how loss and corruption appear in the counters, using
//! `FaultyTransport` to break frames on the sending side.
//!
//! Run with `cargo run --example fault_injection`.

use tpt_link::{FaultyTransport, Link, Loopback};

fn main() {
    let (a, b) = Loopback::pair();
    let mut sender = Link::new(FaultyTransport::new(a));
    let mut receiver = Link::new(b);

    // The first frame fixes the receiver's expected sequence number. Loss
    // before it cannot be seen.
    sender.send(b"0 ok").unwrap();

    sender.transport_mut().drop_next(1);
    sender.send(b"1 dropped").unwrap();
    sender.send(b"2 ok").unwrap();

    sender.transport_mut().corrupt_next(1);
    sender.send(b"3 corrupted").unwrap();
    sender.send(b"4 ok").unwrap();

    for payload in receiver.poll().unwrap() {
        println!("delivered {:?}", String::from_utf8_lossy(&payload));
    }
    // Two frames never arrived (1 and 3), and one of them (3) arrived damaged.
    println!("{:#?}", receiver.stats());
}
