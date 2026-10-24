// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Command-line helper for link frames. It works offline, with no hardware and
//! no network, so it is handy when a frame has been captured from a log or a
//! serial terminal.
//!
//! ```text
//! tpt-link-cli encode <seq> <text>   print the frame for a text payload, as hex
//! tpt-link-cli decode <hex>          print the sequence number and payload
//! tpt-link-cli crc <text>            print the CRC-32 of the text
//! ```
//!
//! Hex may contain spaces. Text is taken as its UTF-8 bytes. Exit status is 0
//! on success and 1 when the input is bad or the frame fails its CRC.

use std::process::ExitCode;

use tpt_link::frame::{crc32, decode, encode};

const USAGE: &str = "usage: tpt-link-cli encode <seq> <text> | decode <hex> | crc <text>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("tpt-link-cli: {message}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let parts: Vec<&str> = args.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["encode", seq, text] => {
            let seq: u32 = seq.parse().map_err(|_| {
                format!("sequence number {seq:?} is not a number from 0 to 4294967295")
            })?;
            let mut wire = Vec::new();
            encode(seq, text.as_bytes(), &mut wire).map_err(|e| e.to_string())?;
            Ok(to_hex(&wire))
        }
        ["decode", hex] => {
            let bytes = from_hex(hex)?;
            let (frame, used) = decode(&bytes).map_err(|e| e.to_string())?;
            let mut out = format!(
                "seq {}\npayload ({} bytes): {:?}",
                frame.seq,
                frame.payload.len(),
                String::from_utf8_lossy(frame.payload)
            );
            if used < bytes.len() {
                out.push_str(&format!("\n{} trailing bytes ignored", bytes.len() - used));
            }
            Ok(out)
        }
        ["crc", text] => Ok(format!("{:#010x}", crc32(text.as_bytes()))),
        _ => Err("unrecognised command".to_string()),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() % 2 == 1 {
        return Err("hex has an odd number of digits".to_string());
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(pair, 16).map_err(|_| format!("{pair:?} is not a hex byte"))
        })
        .collect()
}
