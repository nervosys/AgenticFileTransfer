# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/nervosys/AgenticFileTransfer/security/advisories/new)
  ("Report a vulnerability" under the repository's **Security** tab), or
- email **security@nervosys.com**.

Please include:

- a description of the issue and its impact,
- the version or commit affected,
- steps to reproduce or a proof of concept,
- any suggested mitigation.

We aim to acknowledge a report within a few business days and will keep you
updated as we investigate. Please give us reasonable time to release a fix
before any public disclosure, and avoid privacy violations, data destruction, or
service disruption while researching.

## Supported versions

AFT is released from `master`. Security fixes land on the latest released
version. Until a `1.x` long-term line is designated, only the most recent release
receives security updates.

| Version | Supported |
| ------- | --------- |
| latest (2.x) | ✅ |
| < 2.0   | ❌ |

## Scope and hardening notes

Some security-relevant behavior is intentional and configurable:

- **`--insecure`** disables TLS certificate verification. It is for testing only
  and prints a warning; do not use it against untrusted networks.
- **SFTP/SCP host keys** are verified trust-on-first-use against
  `~/.ssh/known_hosts`; a changed key is refused.
- **The neural-network cipher is experimental and not cryptographically secure.**
  It is gated behind `--experimental-crypto` and must never protect real data.
- **Unauthenticated FEC** (`--fec-insecure`) sends the data plane without
  encryption and requires explicit opt-in on both ends; use only on trusted
  links.
- A **FIPS build** (`--features fips`) routes all bulk crypto through the
  FIPS 140-3 validated `aws-lc-rs` backend.

A detailed security audit of the codebase is maintained in
[`docs/SECURITY.md`](docs/SECURITY.md).
