// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Declares a peer dead when its frames stop. Time is passed in, so the
//! example runs instantly and the output is the same every run.
//!
//! Run with `cargo run --example heartbeat_monitor`.

use tpt_link::{Heartbeat, Link, Loopback};

fn main() {
    let (a, b) = Loopback::pair();
    let mut peer = Link::new(a);
    let mut me = Link::new(b);
    let mut heartbeat = Heartbeat::new(300_000); // 300 ms

    // The peer sends at 0, 100 and 200 ms, then goes quiet.
    for now_us in (0..=700_000u64).step_by(100_000) {
        if now_us <= 200_000 {
            peer.send(b"beat").unwrap();
        }
        if !me.poll().unwrap().is_empty() {
            heartbeat.on_frame(now_us);
        }
        let state = if heartbeat.is_alive(now_us) {
            "alive"
        } else {
            "DEAD"
        };
        println!("{:>4} ms  {state}", now_us / 1000);
    }
}
