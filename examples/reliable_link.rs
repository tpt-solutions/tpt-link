// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Sends 20 readings over a link that loses 30 % of frames in each direction.
//! The channel resends what was lost, so every reading arrives exactly once.
//! Time is injected, so the output is the same every run.
//!
//! Run with `cargo run --example reliable_link`.

use tpt_link::FaultyTransport;
use tpt_link::Loopback;
use tpt_link::reliable::{Channel, ChannelError, Config};

fn main() {
    let config = Config {
        window: 8,
        retransmit_us: 20_000,
        heartbeat_us: 100_000,
        timeout_us: 2_000_000,
    };
    let (a, b) = Loopback::pair();
    let mut a = FaultyTransport::new(a);
    let mut b = FaultyTransport::new(b);
    a.random_loss(300_000, 1);
    b.random_loss(300_000, 2);
    let mut sender = Channel::new(a, config);
    let mut receiver = Channel::new(b, config);

    let readings: Vec<String> = (0..20).map(|i| format!("reading {i}")).collect();
    let mut next = 0;
    let mut now = 0u64;
    let mut received = Vec::new();
    while next < readings.len() || sender.unacked() > 0 {
        while next < readings.len() {
            match sender.send(readings[next].as_bytes(), now) {
                Ok(_) => next += 1,
                Err(ChannelError::WindowFull) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        sender.tick(now).unwrap();
        receiver.tick(now).unwrap();
        for payload in receiver.poll(now).unwrap() {
            received.push(String::from_utf8_lossy(&payload).into_owned());
        }
        sender.poll(now).unwrap();
        now += 1_000;
    }

    println!(
        "delivered {} of {} readings",
        received.len(),
        readings.len()
    );
    println!("sender resent {} messages", sender.retransmits());
    println!("receiver dropped {} repeats", receiver.duplicates());
    // Every reading arrives once, but not necessarily in send order: a resent
    // reading can arrive after the ones sent behind it.
    let mut sorted = received.clone();
    sorted.sort();
    let mut expected = readings.clone();
    expected.sort();
    println!("each reading exactly once: {}", sorted == expected);
    println!("in send order: {}", received == readings);
}
