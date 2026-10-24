// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A client and an echo server on localhost UDP, in one process. Swap the
//! addresses for real hosts to run them on two machines.
//!
//! Run with `cargo run --example udp_echo`.

use std::thread;
use std::time::{Duration, Instant};

use tpt_link::{Link, UdpTransport};

const SERVER: &str = "127.0.0.1:7100";
const CLIENT: &str = "127.0.0.1:7101";

/// Polls until a payload arrives or a second has passed.
fn wait_for<T: tpt_link::Transport>(link: &mut Link<T>) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if let Some(payload) = link.poll().ok()?.into_iter().next() {
            return Some(payload);
        }
        thread::sleep(Duration::from_millis(5));
    }
    None
}

fn main() {
    let server_transport =
        UdpTransport::bind(SERVER, CLIENT.parse().unwrap()).expect("bind server");
    let client_transport =
        UdpTransport::bind(CLIENT, SERVER.parse().unwrap()).expect("bind client");

    let server = thread::spawn(move || {
        let mut link = Link::new(server_transport);
        if let Some(payload) = wait_for(&mut link) {
            link.send(&payload).expect("echo");
        }
    });

    let mut client = Link::new(client_transport);
    client.send(b"ping").expect("send");
    match wait_for(&mut client) {
        Some(reply) => println!("echoed: {:?}", String::from_utf8_lossy(&reply)),
        None => println!("no reply"),
    }
    server.join().expect("server thread");
}
