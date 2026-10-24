// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Keeps a UDP link up. The `Reconnector` decides when to open the socket, and
//! the `Heartbeat` decides when an open link has gone quiet. The first two
//! opens are made to fail, so the backoff is visible. A peer thread sends for
//! three seconds and then goes silent, so the heartbeat timeout is also visible.
//!
//! Run with `cargo run --example reconnect`.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use tpt_link::reconnect::{Action, Reconnector};
use tpt_link::{Heartbeat, Link, UdpTransport};

const LOCAL: &str = "127.0.0.1:7000";
const PEER: &str = "127.0.0.1:7001";
const HEARTBEAT_TIMEOUT_US: u64 = 200_000;
const TICK: Duration = Duration::from_millis(20);
const TICKS: u32 = 300;

/// Stands in for opening the real transport. Fails twice, as a peer that is
/// not up yet would.
fn connect(peer: SocketAddr, attempt: u32) -> io::Result<UdpTransport> {
    if attempt <= 2 {
        return Err(io::Error::new(ErrorKind::ConnectionRefused, "peer not up"));
    }
    UdpTransport::bind(LOCAL, peer)
}

fn main() {
    let peer_thread = thread::spawn(|| {
        let peer =
            UdpTransport::bind(PEER, LOCAL.parse().expect("valid address")).expect("bind peer");
        let mut link = Link::new(peer);
        for _ in 0..60 {
            // The client may not be listening yet, so send errors are ignored.
            let _ = link.send(b"alive");
            thread::sleep(Duration::from_millis(50));
        }
    });

    let start = Instant::now();
    let now_us = || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let peer: SocketAddr = PEER.parse().expect("valid peer address");

    let mut reconnector = Reconnector::new(100_000, 1_000_000);
    let mut heartbeat = Heartbeat::new(HEARTBEAT_TIMEOUT_US);
    let mut link: Option<Link<UdpTransport>> = None;
    let mut attempts = 0;

    reconnector.on_link_down(now_us());
    for _ in 0..TICKS {
        let now = now_us();

        if reconnector.is_up() && !heartbeat.is_alive(now) {
            println!("{now:>10} us  heartbeat silent, link down");
            reconnector.on_link_down(now);
            link = None;
        }

        if !reconnector.is_up() && reconnector.tick(now) == Action::Attempt {
            attempts += 1;
            match connect(peer, attempts) {
                Ok(transport) => {
                    println!("{now:>10} us  attempt {attempts}: connected");
                    link = Some(Link::new(transport));
                    reconnector.on_connected();
                    // Opening the socket counts as the first sign of life, so the
                    // timeout runs from here.
                    heartbeat.on_frame(now);
                }
                Err(e) => println!("{now:>10} us  attempt {attempts}: {e}"),
            }
        }

        if let Some(active) = link.as_mut() {
            match active.poll() {
                Ok(payloads) => {
                    if !payloads.is_empty() {
                        heartbeat.on_frame(now);
                    }
                }
                Err(e) => {
                    println!("{now:>10} us  transport error: {e}");
                    reconnector.on_link_down(now);
                    link = None;
                }
            }
        }

        thread::sleep(TICK);
    }
    peer_thread.join().expect("peer thread");
}
