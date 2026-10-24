## What and why

<!-- One or two sentences. Link the TODO.md item or issue if there is one. -->

## Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings` (and `--all-features`)
- [ ] `cargo test --all-targets` (and `cargo test --lib --no-default-features`)
- [ ] A regression test for each bug fixed
- [ ] `spec.txt` and `CHANGELOG.md` updated if behaviour changed

## Wire format

- [ ] No change to the wire format, or the change is in spec.txt with a new version

## Platforms tested

<!-- For example: Windows 11 local, Linux via CI. Say what you could not run. -->
