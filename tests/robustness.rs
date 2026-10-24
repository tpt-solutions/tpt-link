// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Randomised but repeatable checks on hostile input. Each run uses a fixed
//! seed, so a failure can be replayed. They look for panics and for invariants
//! that must hold for any input, rather than for particular values.

use std::collections::HashSet;
use std::convert::Infallible;

use tpt_link::Link;
use tpt_link::can::{CLASSIC_MTU, CanBus, CanTransport, VirtualBus, VirtualNode};
use tpt_link::frame::{VERSION, decode, encode};
use tpt_link::stream::Deframer;

/// A small linear congruential generator. Only for choosing test inputs.
struct Rng(u64);

impl Rng {
    fn word(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: u64) -> u64 {
        self.word() % n
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.word() as u8).collect()
    }
}

#[test]
fn decode_never_panics_and_only_accepts_what_encode_produces() {
    let mut rng = Rng(1);
    for _ in 0..20_000 {
        let len = rng.below(64) as usize;
        let mut input = rng.bytes(len);
        // Make the version check pass often, so the later checks run too.
        if len > 0 && rng.below(2) == 0 {
            input[0] = VERSION;
        }
        if let Ok((frame, used)) = decode(&input) {
            let mut wire = Vec::new();
            encode(frame.seq, frame.payload, &mut wire).unwrap();
            assert_eq!(wire, input[..used]);
        }
    }
}

#[test]
fn every_frame_is_recovered_from_a_noisy_stream() {
    let mut rng = Rng(2);
    let mut stream = Vec::new();
    let mut sent = Vec::new();
    for seq in 0..60u32 {
        let noise_len = rng.below(40) as usize;
        stream.extend(rng.bytes(noise_len));
        let payload_len = rng.below(200) as usize;
        let mut wire = Vec::new();
        encode(seq, &rng.bytes(payload_len), &mut wire).unwrap();
        stream.extend_from_slice(&wire);
        sent.push(wire);
    }

    // A noise byte can look like a frame that claims more bytes than follow it.
    // The deframer then waits for those bytes, so the timeout must drive it.
    let mut deframer = Deframer::with_timeout(1_000);
    deframer.push_at(&stream, 0);
    let mut now = 0u64;
    let mut got = Vec::new();
    let mut idle_calls = 0;
    loop {
        match deframer.next_frame_at(now) {
            Some(frame) => got.push(frame),
            None => {
                if deframer.buffered() == 0 {
                    break;
                }
                idle_calls += 1;
                assert!(idle_calls < 100_000, "deframer did not drain");
                now += 1_000;
            }
        }
    }
    assert_eq!(got, sent);
}

/// A bus node that loses a share of the frames it sends, as a noisy bus would.
struct Lossy {
    inner: VirtualNode,
    rng: Rng,
    loss_per_mille: u64,
}

impl CanBus for Lossy {
    type Error = Infallible;

    fn send_raw(&mut self, id: u16, data: &[u8]) -> Result<(), Infallible> {
        if self.rng.below(1_000) < self.loss_per_mille {
            return Ok(());
        }
        self.inner.send_raw(id, data)
    }

    fn recv_raw(&mut self) -> Result<Option<(u16, Vec<u8>)>, Infallible> {
        self.inner.recv_raw()
    }
}

#[test]
fn lost_fragments_never_yield_a_payload_that_was_not_sent() {
    // Message ids wrap every 256 messages, so over 1000 messages a partial message
    // left behind by a lost fragment is often reached by a later message with
    // the same id. The link CRC has to reject any splice that results.
    let bus = VirtualBus::new();
    let mut sender = Link::new(
        CanTransport::new(
            Lossy {
                inner: bus.attach(),
                rng: Rng(3),
                loss_per_mille: 100,
            },
            1,
            CLASSIC_MTU,
            1_000_000,
        )
        .unwrap(),
    );
    let mut receiver =
        Link::new(CanTransport::new(bus.attach(), 2, CLASSIC_MTU, 1_000_000).unwrap());

    let mut rng = Rng(4);
    let mut sent = HashSet::new();
    let mut delivered = Vec::new();
    for _ in 0..1_000 {
        let payload_len = 1 + rng.below(40) as usize;
        let payload = rng.bytes(payload_len);
        sender.send(&payload).unwrap();
        sent.insert(payload);
        delivered.extend(receiver.poll().unwrap());
    }

    for payload in &delivered {
        assert!(
            sent.contains(payload),
            "delivered a payload that was never sent"
        );
    }
    // With 10 % fragment loss most messages still arrive. This guards against
    // the test passing only because nothing was delivered.
    assert!(delivered.len() > 300, "only {} delivered", delivered.len());
}
