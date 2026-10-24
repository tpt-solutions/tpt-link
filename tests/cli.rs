// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Runs the `tpt-link-cli` binary and checks what it prints.

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tpt-link-cli"))
        .args(args)
        .output()
        .expect("run tpt-link-cli")
}

fn stdout_of(args: &[&str]) -> String {
    let out = cli(args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn crc_prints_the_check_value() {
    assert_eq!(stdout_of(&["crc", "123456789"]).trim(), "0xcbf43926");
}

#[test]
fn an_encoded_frame_decodes_back() {
    let hex = stdout_of(&["encode", "7", "hello"]);
    let decoded = stdout_of(&["decode", hex.trim()]);
    assert!(decoded.contains("seq 7"), "{decoded}");
    assert!(decoded.contains("\"hello\""), "{decoded}");
}

#[test]
fn hex_with_spaces_is_accepted() {
    let hex = stdout_of(&["encode", "1", "hi"]);
    let spaced: String = hex
        .trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(stdout_of(&["decode", &spaced]).contains("seq 1"));
}

#[test]
fn a_damaged_frame_fails_with_the_crc_message() {
    let mut hex = stdout_of(&["encode", "1", "hi"]).trim().to_string();
    // Change the last hex digit, which lies in the CRC.
    let last = hex.pop().unwrap();
    hex.push(if last == '0' { '1' } else { '0' });

    let out = cli(&["decode", &hex]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CRC mismatch"));
}

#[test]
fn bad_input_is_reported_with_usage() {
    let out = cli(&["decode", "abc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("odd number"), "{stderr}");
    assert!(stderr.contains("usage:"), "{stderr}");
}
