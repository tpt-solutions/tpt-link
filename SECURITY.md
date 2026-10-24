# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: the **Security** tab of this repository, then
**Report a vulnerability**. That opens a private advisory that only the
maintainers can see.

Include:

- the version or commit you tested
- the feature flags in use (`auth`, `serial`, `can-socketcan`, and so on)
- a description of the impact, and steps or a test case that reproduces it

We aim to acknowledge a report within a week. We will agree a disclosure date with
you before publishing a fix.

## Scope

tpt-link is a wire layer. The following are in scope:

- the frame decoder, the deframer and the fragmentation reassembly, for panics,
  unbounded memory use, or accepting damaged data
- the `auth` feature: sealing, replay protection, key exchange and key rotation

The threat model for the authenticated link is in
[docs/auth-threat-model.md](docs/auth-threat-model.md). It lists what the layer
does not protect against. Reports that only restate a documented limitation are
still welcome, but they are handled as hardening work rather than as a
vulnerability.

Signing keys and pre-shared keys are the application's responsibility. Never
commit them. `.gitignore` excludes common key file types, but it is not a
guarantee.
