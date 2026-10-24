// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Round trip over a real SocketCAN virtual interface. Linux only, and it needs
//! `vcan0` to exist. CI creates it. Locally, see `src/can_socketcan.rs`.

#![cfg(all(feature = "can-socketcan", target_os = "linux"))]

use std::thread;
use std::time::{Duration, Instant};

use tpt_link::Transport;
use tpt_link::can::{CLASSIC_MTU, CanTransport};
use tpt_link::can_socketcan::SocketCanBus;

const IFACE: &str = "vcan0";
const DEADLINE: Duration = Duration::from_secs(5);

fn receive(rx: &mut CanTransport<SocketCanBus>) -> Option<Vec<u8>> {
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        if let Some(frame) = rx.try_recv().expect("receive") {
            return Some(frame);
        }
        thread::sleep(Duration::from_millis(1));
    }
    None
}

#[test]
fn link_frame_round_trips_over_vcan() {
    let bus_a = SocketCanBus::open(IFACE).expect("open vcan0: see src/can_socketcan.rs");
    let bus_b = SocketCanBus::open(IFACE).expect("open vcan0");
    let mut a = CanTransport::new(bus_a, 1, CLASSIC_MTU, 1_000_000).unwrap();
    let mut b = CanTransport::new(bus_b, 2, CLASSIC_MTU, 1_000_000).unwrap();

    let payload = vec![0x5A; 1024];
    let mut wire = Vec::new();
    tpt_link::frame::encode(7, &payload, &mut wire).unwrap();

    a.send(&wire).unwrap();
    assert_eq!(receive(&mut b), Some(wire));
    // The sender must not see its own frames.
    assert_eq!(a.try_recv().unwrap(), None);
}
