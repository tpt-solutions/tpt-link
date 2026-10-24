# Contributing to tpt-link

Thanks for looking at tpt-link. It is the shared wire layer for the TPT
ecosystem, so changes here affect every repo that links against it.

Contributions are accepted as issues only. Please do not open pull requests;
they will be closed. Describe the bug, the missing feature, or the change you
want in a new issue, and the maintainers will take it from there.

## Before you open an issue

- Read [spec.txt](spec.txt). It is the contract. A request that alters the wire
  format, the CRC, or a decoding rule needs a spec change and a version bump.
- Check [TODO.md](TODO.md) and the existing issues for open items first.

## What a good issue includes

- What you expected to happen, and what happened instead.
- The platform, the Rust version, and the crate version or commit you used.
- A minimal reproduction, or the test case that fails, if you have one.
- For a proposed change, the part of [spec.txt](spec.txt) it touches.

## Project rules

These apply to any change the maintainers make, and they shape which requests
can be accepted:

- **Wire format is frozen at version 1.** Existing fields, the CRC, and the
  byte order do not change. A new version is added instead.
- **Every fix gets a regression test.**
- **No new dependencies without a licence check.** The crate is MIT OR
  Apache-2.0, and dependencies must be permissive.
- **Keep the core `no_std`.** Frame decoding needs only `core`. Code that needs
  the heap goes behind `alloc`, and code that needs the OS goes behind `std`.
- **Time is injected.** Protocol logic takes a `now_us` argument rather than
  reading a global clock.
- **Generated code is regenerated, not edited.** `src/schema.rs` comes from
  `tools/gen-schema`.

## Licence

The project is licensed under MIT OR Apache-2.0. Ideas and reports submitted as
issues are used under the same terms.
