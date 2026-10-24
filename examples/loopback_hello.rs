// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The smallest send and receive: two links joined by an in-memory channel.
//!
//! Run with `cargo run --example loopback_hello`.

use tpt_link::{Link, Loopback};

fn main() {
    let (a, b) = Loopback::pair();
    let mut sender = Link::new(a);
    let mut receiver = Link::new(b);

    sender.send(b"hello").expect("send");
    for payload in receiver.poll().expect("poll") {
        println!("received {:?}", String::from_utf8_lossy(&payload));
    }
    println!("{:?}", receiver.stats());
}
