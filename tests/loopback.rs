// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Loopback harness: two `Link`s talk over an in-memory channel, with faults
//! injected on the sending side.

use tpt_link::{Closed, FaultyTransport, Heartbeat, Link, LinkError, Loopback};

type Faulty = FaultyTransport<Loopback>;

fn linked_pair() -> (Link<Faulty>, Link<Loopback>) {
    let (a, b) = Loopback::pair();
    (Link::new(FaultyTransport::new(a)), Link::new(b))
}

#[test]
fn payloads_arrive_in_order_with_no_loss() {
    let (mut a, mut b) = linked_pair();
    for i in 0..5u8 {
        assert_eq!(a.send(&[i]).unwrap(), u32::from(i));
    }

    let got = b.poll().unwrap();
    assert_eq!(got, (0..5u8).map(|i| vec![i]).collect::<Vec<_>>());
    assert_eq!(b.stats().received, 5);
    assert_eq!(b.stats().lost, 0);
    assert_eq!(a.stats().sent, 5);
}

#[test]
fn dropped_frame_is_counted_as_lost() {
    let (mut a, mut b) = linked_pair();
    a.send(b"one").unwrap();
    a.transport_mut().drop_next(1);
    a.send(b"two").unwrap();
    a.send(b"three").unwrap();

    assert_eq!(b.poll().unwrap(), vec![b"one".to_vec(), b"three".to_vec()]);
    assert_eq!(b.stats().lost, 1);
    assert_eq!(b.stats().crc_errors, 0);
}

#[test]
fn corrupted_frame_is_dropped_and_counted() {
    let (mut a, mut b) = linked_pair();
    // Establish the sequence first. Loss before the first received frame
    // cannot be seen, because the receiver has no expected number yet.
    a.send(b"ok").unwrap();
    assert_eq!(b.poll().unwrap(), vec![b"ok".to_vec()]);

    a.transport_mut().corrupt_next(1);
    a.send(b"damaged").unwrap();
    a.send(b"fine").unwrap();

    // The damaged frame never reaches the caller. Its sequence number is lost
    // with it, so the gap shows up as one lost frame.
    assert_eq!(b.poll().unwrap(), vec![b"fine".to_vec()]);
    assert_eq!(b.stats().crc_errors, 1);
    assert_eq!(b.stats().lost, 1);
}

#[test]
fn oversize_payload_is_a_frame_error_not_sent() {
    let (mut a, mut b) = linked_pair();
    let huge = vec![0u8; tpt_link::frame::MAX_PAYLOAD_LEN + 1];
    assert!(matches!(a.send(&huge), Err(LinkError::Frame(_))));
    assert_eq!(a.stats().sent, 0);
    assert!(b.poll().unwrap().is_empty());
}

#[test]
fn peer_disconnect_is_reported_by_poll() {
    let (a, b) = Loopback::pair();
    let mut b = Link::new(b);
    drop(a);

    match b.poll() {
        Err(LinkError::Transport(Closed)) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[test]
fn heartbeat_follows_traffic_and_detects_silence() {
    let (mut a, mut b) = linked_pair();
    let mut heartbeat = Heartbeat::new(100_000);

    a.send(b"alive").unwrap();
    let arrived = b.poll().unwrap();
    assert_eq!(arrived.len(), 1);
    heartbeat.on_frame(1_000);
    assert!(heartbeat.is_alive(101_000));

    // No more traffic: the link is declared dead once the timeout passes.
    assert!(!heartbeat.is_alive(101_001));
}

#[test]
fn sequence_numbers_wrap_without_counting_false_loss() {
    let (a, b) = Loopback::pair();
    let mut a = Link::new(a);
    let mut b = Link::new(b);

    // Start the sender near the top of the sequence space.
    a.set_next_seq(u32::MAX - 1);
    for payload in [b"x", b"y", b"z"] {
        a.send(payload).unwrap();
    }

    assert_eq!(b.poll().unwrap().len(), 3);
    assert_eq!(b.stats().lost, 0);
}

fn raw_frame(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    tpt_link::frame::encode(seq, payload, &mut wire).unwrap();
    wire
}

#[test]
fn payloads_survive_a_transport_error_that_follows_them() {
    let (a, b) = Loopback::pair();
    let mut a = Link::new(a);
    let mut b = Link::new(b);
    a.send(b"one").unwrap();
    a.send(b"two").unwrap();
    drop(a);

    assert_eq!(b.poll().unwrap(), vec![b"one".to_vec(), b"two".to_vec()]);
    assert!(matches!(b.poll(), Err(LinkError::Transport(Closed))));
}

#[test]
fn every_frame_in_one_datagram_is_delivered() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    let mut both = raw_frame(0, b"first");
    both.extend(raw_frame(1, b"second"));
    a.send(&both).unwrap();

    assert_eq!(
        b.poll().unwrap(),
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert_eq!(b.stats().received, 2);
    assert_eq!(b.stats().lost, 0);
}

#[test]
fn reordered_frame_is_not_counted_as_extra_loss() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    for seq in [0, 2, 1, 3] {
        a.send(&raw_frame(seq, b"x")).unwrap();
    }

    b.poll().unwrap();
    // Frame 1 was only late, so the single gap seen at frame 2 is the whole count.
    assert_eq!(b.stats().lost, 1);
}

#[test]
fn peer_restart_resyncs_the_sequence() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    for seq in [1000, 1001, 0, 1, 2] {
        a.send(&raw_frame(seq, b"x")).unwrap();
    }

    assert_eq!(b.poll().unwrap().len(), 5);
    assert_eq!(b.stats().lost, 0);
}

#[test]
fn unknown_version_is_counted_separately_from_crc_errors() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    let mut wire = raw_frame(0, b"x");
    wire[0] = 9;
    a.send(&wire).unwrap();

    assert!(b.poll().unwrap().is_empty());
    assert_eq!(b.stats().bad_version, 1);
    assert_eq!(b.stats().crc_errors, 0);
}

#[test]
fn duplicate_frame_is_dropped_and_counted() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    for seq in [0, 1, 1, 2] {
        a.send(&raw_frame(seq, b"x")).unwrap();
    }

    assert_eq!(b.poll().unwrap().len(), 3);
    assert_eq!(b.stats().duplicates, 1);
    assert_eq!(b.stats().lost, 0);
}

#[test]
fn late_frame_fills_its_gap_and_its_repeat_is_dropped() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    for seq in [0, 2, 1, 1] {
        a.send(&raw_frame(seq, &[seq as u8])).unwrap();
    }

    let got = b.poll().unwrap();
    assert_eq!(got, vec![vec![0], vec![2], vec![1]]);
    assert_eq!(b.stats().duplicates, 1);
    assert_eq!(b.stats().lost, 1);
}

#[test]
fn frame_older_than_the_window_is_taken_as_a_restart() {
    use tpt_link::Transport;

    let (mut a, b) = Loopback::pair();
    let mut b = Link::new(b);
    for seq in [0, 200, 0] {
        a.send(&raw_frame(seq, b"x")).unwrap();
    }

    assert_eq!(b.poll().unwrap().len(), 3);
    assert_eq!(b.stats().lost, 199);
    assert_eq!(b.stats().duplicates, 0);
}
