# Contributing to tpt-link

Thanks for looking at tpt-link. It is the shared wire layer for the TPT
ecosystem, so changes here affect every repo that links against it.

## Before you start

- Read [spec.txt](spec.txt). It is the contract. A change that alters the wire
  format, the CRC, or a decoding rule needs a spec change and a version bump.
- Check [TODO.md](TODO.md) for open items, and open an issue before starting
  anything large.

## Checks

CI runs all of these. Run the ones that match your change before pushing:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --lib --no-default-features
cargo deny check licenses bans sources advisories
```

The toolchain is pinned in `rust-toolchain.toml`. The minimum supported Rust
version is 1.85 (`proto` needs 1.88).

## Rules for changes

- **Wire format is frozen at version 1.** Do not change an existing field,
  the CRC, or the byte order. Add a new version instead.
- **Every fix gets a regression test.** Name the test after the behaviour it
  pins, not the bug number.
- **No new dependencies without a licence check.** The crate is MIT OR
  Apache-2.0 and `deny.toml` allows only permissive licences. Anything that is
  Apache-2.0 alone, or proprietary, fails CI.
- **Keep the core `no_std`.** Frame decoding needs only `core`. Code that needs
  the heap goes behind `alloc`, and code that needs the OS goes behind `std`.
- **Time is injected.** Do not read a global clock inside the protocol logic.
  Take a `now_us` argument instead, so tests stay exact.
- **Generated code is regenerated, not edited.** `src/schema.rs` comes from
  `tools/gen-schema`. CI fails if it drifts.

## Commits and pull requests

- Keep commits focused. Describe what changed and why in the body.
- Fill in the pull request template. Say which tests you ran and on which
  platform.
- A change to `spec.txt` belongs in the same pull request as the code it
  describes.

## Licence

By contributing you agree that your contribution is licensed under the same
terms as the project: MIT OR Apache-2.0.
