# Contributing to AFT

Thanks for your interest in Agentic File Transfer. This guide covers how to build,
test, and submit changes.

## Development setup

AFT is a Rust project (MSRV **1.75**). No special toolchain is required for the
default build.

```bash
git clone https://github.com/nervosys/AgenticFileTransfer
cd AgenticFileTransfer
cargo build
cargo test
```

The optional FIPS build routes crypto through the validated `aws-lc-rs` backend
and needs a C/C++ toolchain (cmake, clang/gcc):

```bash
cargo build --features fips
```

## Before you open a pull request

Every change must pass the same gates CI enforces:

```bash
cargo fmt --all --check        # formatting
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features fips -- -D warnings
cargo test                     # unit + integration
```

Please also:

- Keep changes focused; one logical change per PR.
- Match the surrounding code's style, naming, and comment density.
- Add or update tests for behavior you change.
- Update `docs/CHANGELOG.md` under an `## [Unreleased]` heading when your change
  is user-visible.
- Never commit secrets. Tokens and endpoints are supplied at runtime (e.g. the
  telemetry collector's `OTEL_EXPORTER_OTLP_HEADERS`); `.env` and key files are
  git-ignored.

## Developer Certificate of Origin (DCO)

AFT is dual-licensed (AGPL-3.0-or-later **and** a commercial license — see
[LICENSING.md](LICENSING.md)). For the project to keep offering the commercial
option, every contribution must be one you have the right to submit under the
project's inbound license.

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off each commit to certify it:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line. By signing off
you agree to the DCO and that your contribution is provided under the
AGPL-3.0-or-later and may also be licensed by Nervosys under its commercial
license. For substantial contributions we may ask you to sign a Contributor
License Agreement (CLA); we'll let you know if that applies.

## Reporting bugs and security issues

- **Bugs / features:** open a GitHub issue with steps to reproduce.
- **Security vulnerabilities:** do **not** open a public issue — see
  [SECURITY.md](SECURITY.md) for private reporting.

## License of contributions

Unless you state otherwise, contributions you submit are provided under the
project's inbound license, AGPL-3.0-or-later (inbound = outbound), per the DCO
above.
