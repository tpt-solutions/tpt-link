// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A valve controller and a host on localhost UDP, both keyed with the same
//! secret. An intruder without the key sends a frame too.
//!
//! The controller drops the intruder's frame for a different reason than the
//! tag check. Its source address is not the host's, so the transport's peer
//! filter drops it first. A spoofed source address would pass that filter. Then
//! only the tag stops the frame, and the unit tests in `auth` cover that case.
//!
//! Run with `cargo run --example authenticated_udp --features auth`.

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use tpt_link::auth::{Authenticated, KEY_LEN, Key};
use tpt_link::frame::encode;
use tpt_link::{Link, UdpTransport};

const CONTROLLER: &str = "127.0.0.1:7300";
const HOST: &str = "127.0.0.1:7301";

fn main() {
    // A real device would load this from secure storage. It is fixed here so the
    // example runs.
    let key = Key::new([0x42; KEY_LEN]);

    let controller_transport = UdpTransport::bind(CONTROLLER, HOST.parse().unwrap()).expect("bind");
    let mut controller = Link::new(Authenticated::new(controller_transport, key.clone()));

    // The intruder knows the address but not the key, so it sends a plain frame.
    let mut forged = Vec::new();
    encode(0, b"open valve 100%", &mut forged).unwrap();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(&forged, CONTROLLER)
        .unwrap();

    let host_transport = UdpTransport::bind(HOST, CONTROLLER.parse().unwrap()).expect("bind");
    let mut host = Link::new(Authenticated::new(host_transport, key));
    host.send(b"open valve 40%").unwrap();

    // Localhost delivers in order, but give the datagrams a moment to land.
    thread::sleep(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut accepted = Vec::new();
    while accepted.is_empty() && Instant::now() < deadline {
        accepted.extend(controller.poll().expect("poll"));
        thread::sleep(Duration::from_millis(5));
    }

    for command in &accepted {
        println!("controller acts on {:?}", String::from_utf8_lossy(command));
    }
    let auth = controller.transport_mut();
    println!("dropped by the peer filter: {}", auth.inner_mut().foreign());
    println!("dropped by the tag check: {}", auth.rejected());
}
