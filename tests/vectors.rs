// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Checks the frame codec against `testdata/vectors.json`. The vectors were
//! produced by an independent implementation (Python `zlib.crc32`), so this
//! test catches a CRC or layout mistake that a round trip alone would miss.

use tpt_link::frame::{self, FrameError};

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn load() -> serde_json::Value {
    let text = include_str!("../testdata/vectors.json");
    serde_json::from_str(text).expect("vectors.json parses")
}

#[test]
fn encode_matches_golden_bytes() {
    let doc = load();
    assert_eq!(doc["version"], frame::VERSION);
    for v in doc["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let seq = u32::try_from(v["seq"].as_u64().unwrap()).unwrap();
        let payload = from_hex(v["payload_hex"].as_str().unwrap());
        let want = from_hex(v["wire_hex"].as_str().unwrap());

        let mut got = Vec::new();
        frame::encode(seq, &payload, &mut got).unwrap();
        assert_eq!(got, want, "encode mismatch for {name}");
    }
}

#[test]
fn decode_golden_bytes() {
    let doc = load();
    for v in doc["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let seq = u32::try_from(v["seq"].as_u64().unwrap()).unwrap();
        let payload = from_hex(v["payload_hex"].as_str().unwrap());
        let wire = from_hex(v["wire_hex"].as_str().unwrap());

        let (frame, used) = frame::decode(&wire).unwrap();
        assert_eq!(frame.seq, seq, "seq for {name}");
        assert_eq!(frame.payload, payload.as_slice(), "payload for {name}");
        assert_eq!(used, wire.len(), "length for {name}");
    }
}

#[test]
fn flipping_any_byte_fails_the_crc_or_the_header() {
    let doc = load();
    let first = &doc["vectors"][1];
    let wire = from_hex(first["wire_hex"].as_str().unwrap());

    for i in 0..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 0x01;
        let result = frame::decode(&bad);
        match i {
            0 => assert!(matches!(result, Err(FrameError::BadVersion(_)))),
            // A changed length can point past the end or over the limit, and a
            // changed seq is caught by the CRC. Any of these errors is correct.
            1..=6 => assert!(
                matches!(
                    result,
                    Err(FrameError::BadCrc { .. }
                        | FrameError::Truncated
                        | FrameError::TooLarge(_))
                ),
                "flip at byte {i}: {result:?}"
            ),
            _ => assert!(
                matches!(result, Err(FrameError::BadCrc { .. })),
                "flip at byte {i}: {result:?}"
            ),
        }
    }
}
