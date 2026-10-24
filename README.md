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

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --features serial
cargo deny check licenses bans sources
```

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Copyright (c) 2026 TPT Solutions.
