// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A `Session` sends heartbeats by itself and notices when the peer goes quiet.
//! Time is injected, so the output is the same every run.
//!
//! Run with `cargo run --example session`.

use tpt_link::Loopback;
use tpt_link::envelope::{Message, Session};

fn main() {
    let (a, b) = Loopback::pair();
    // Heartbeat every 100 ms; the peer is dead after 250 ms of silence.
    let mut device = Session::new(a, 100_000, 250_000);
    let mut host = Session::new(b, 100_000, 250_000);

    for now_us in (0..=700_000u64).step_by(50_000) {
        let ms = now_us / 1000;
        // The device runs until 300 ms and then stops, as if it had crashed.
        if now_us <= 300_000 {
            device.tick(now_us).unwrap();
            if now_us == 150_000 {
                device.send_data(b"reading=21.5").unwrap();
            }
        }
        for message in host.poll_at(now_us).unwrap() {
            match message {
                Message::Data(body) => {
                    println!("{ms:>4} ms  data {:?}", String::from_utf8_lossy(&body));
                }
                other => println!("{ms:>4} ms  {other:?}"),
            }
        }
        if !host.is_alive(now_us) {
            println!("{ms:>4} ms  peer is silent");
        }
    }
}
