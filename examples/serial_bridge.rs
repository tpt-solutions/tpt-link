// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Bridges a serial or USB-CDC port to a UDP peer. Each link frame is forwarded
//! unchanged in both directions, so the sequence numbers and CRCs pass through
//! and the two ends still see one link.
//!
//! Needs hardware to try it: a device on the port, and a UDP peer to talk to.
//! It only compiles here without one.
//!
//! ```text
//! cargo run --example serial_bridge --features serial -- COM3 115200 0.0.0.0:7200 192.168.1.20:7200
//! ```
//!
//! Arguments: serial port, baud rate, local UDP address, UDP peer address.

use std::error::Error;
use std::thread;
use std::time::Duration;

use tpt_link::serial::SerialTransport;
use tpt_link::{Transport, UdpTransport};

/// How long to wait when neither side had anything to forward.
const IDLE: Duration = Duration::from_millis(1);

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [port, baud, local, peer] = args.as_slice() else {
        eprintln!("usage: serial_bridge <port> <baud> <local udp addr> <peer udp addr>");
        std::process::exit(2);
    };

    let mut serial = SerialTransport::open(port, baud.parse()?)?;
    let mut udp = UdpTransport::bind(local.as_str(), peer.parse()?)?;
    println!("bridging {port} at {baud} bps and {local} <-> {peer}");

    let mut forwarded = 0u64;
    loop {
        let mut busy = false;

        if let Some(frame) = serial.try_recv()? {
            udp.send(&frame)?;
            forwarded += 1;
            busy = true;
        }
        if let Some(frame) = udp.try_recv()? {
            serial.send(&frame)?;
            forwarded += 1;
            busy = true;
        }

        if !busy {
            thread::sleep(IDLE);
        }
        if busy && forwarded % 1000 == 0 {
            println!(
                "{forwarded} frames forwarded, {} serial stalls",
                serial.stalls()
            );
        }
    }
}
