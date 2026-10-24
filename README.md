# tpt-link

Shared wire layer for the TPT ecosystem: the frame format, transports, sequencing,
heartbeat and reconnect policy. See [spec.txt](spec.txt) for the specification.

## Use

```toml
[dependencies]
tpt-link = { path = "../tpt-link" }                      # full std build
tpt-link = { path = "../tpt-link", default-features = false }  # no_std frame codec
```

Features: `std` (default), `alloc`, `serial`. See spec section 9.

## Features in brief

- **Frames**: versioned, CRC-32 checked, sequenced (`frame`).
- **Byte streams**: a deframer finds frames in serial or USB-CDC data, with a
  stall timeout for corrupted length fields (`stream`).
- **Transports**: `Loopback`, `UdpTransport`, `SerialTransport` (feature
  `serial`), and `FaultyTransport` for tests.
- **Link**: sequence numbers, loss counts, a `Heartbeat` for liveness, and a
  `Reconnector` with exponential backoff. See `examples/reconnect.rs`.
- **Fragmentation**: splits messages larger than a small MTU, and reassembles them
  with expiry (`fragment`).
- **CAN**: `CanTransport` carries link frames over any `CanBus`. `SocketCanBus`
  (feature `can-socketcan`, Linux) and `VirtualBus` for tests are included.
- **Protobuf core**: `Heartbeat`, `Ack` and `Error` in `proto/tpt_link.proto`,
  generated into `schema` (feature `proto`). Regenerate with
  `cargo run --manifest-path tools/gen-schema/Cargo.toml`, which needs `protoc`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --features serial
cargo run --example reconnect
cargo test --features proto
cargo test --features can-socketcan --test socketcan   # Linux, needs vcan0
cargo deny check licenses bans sources advisories
```

CI (`.github/workflows/ci.yml`) runs these checks on Linux, Windows and macOS,
and builds the core for the MCU targets `thumbv7em-none-eabihf` and
`riscv32imc-unknown-none-elf`.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Copyright (c) 2026 TPT Solutions.
