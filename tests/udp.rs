// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! UDP transport over localhost. Two sockets talk to each other through the
//! real network stack.

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use tpt_link::{Link, Transport, UdpTransport};

/// Binds a socket to an OS-chosen localhost port, to learn its address before
/// the peer is set up.
fn free_addr() -> SocketAddr {
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap()
}

/// Polls until a frame arrives or a second has passed. localhost delivery is
/// fast, but not synchronous with `send`.
fn recv_within_1s<T: Transport>(t: &mut T) -> Option<Vec<u8>>
where
    T::Error: std::fmt::Debug,
{
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(frame) = t.try_recv().unwrap() {
            return Some(frame);
        }
        if Instant::now() > deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn frame_round_trips_over_localhost_udp() {
    let a_addr = free_addr();
    let b_addr = free_addr();
    let mut a = UdpTransport::bind(a_addr, b_addr).unwrap();
    let mut b = UdpTransport::bind(b_addr, a_addr).unwrap();

    a.send(b"hello over udp").unwrap();
    assert_eq!(
        recv_within_1s(&mut b).as_deref(),
        Some(&b"hello over udp"[..])
    );
}

#[test]
fn try_recv_does_not_block_when_idle() {
    let mut t = UdpTransport::bind("127.0.0.1:0", free_addr()).unwrap();
    let started = Instant::now();
    assert_eq!(t.try_recv().unwrap(), None);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn link_sequencing_works_over_udp() {
    let a_addr = free_addr();
    let b_addr = free_addr();
    let mut a = Link::new(UdpTransport::bind(a_addr, b_addr).unwrap());
    let mut b = Link::new(UdpTransport::bind(b_addr, a_addr).unwrap());

    for payload in [&b"one"[..], b"two", b"three"] {
        a.send(payload).unwrap();
    }

    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    while got.len() < 3 && Instant::now() < deadline {
        got.extend(b.poll().unwrap());
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        got,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    assert_eq!(b.stats().lost, 0);
}

#[test]
fn datagrams_from_other_addresses_are_dropped() {
    let mut a = UdpTransport::bind("127.0.0.1:0", "127.0.0.1:9".parse().unwrap()).unwrap();
    let intruder = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    intruder
        .send_to(b"injected", a.local_addr().unwrap())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(a.try_recv().unwrap(), None);
    assert_eq!(a.foreign(), 1);
}
