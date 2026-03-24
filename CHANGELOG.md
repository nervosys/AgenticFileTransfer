# Changelog

All notable changes to AFT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-23

### Added

- **AFTP binary protocol** — custom wire protocol with 10-byte frame headers,
  21+ frame types, and 0.001% framing overhead per 1 MB data frame.
- **Session resume** — MOSH-inspired intermittent connection support with
  RESUME/RESUME_ACK frames, server-side session store, and automatic reconnect.
- **Post-quantum cryptography** — ML-KEM (Kyber1024) key encapsulation with
  AES-256-GCM hybrid encryption for quantum-resistant file transfers.
- **Neural network cipher** — experimental MLP autoencoder cipher with
  OFB-mode block encryption (research only, not for production).
- **DoD classification markings** — Executive Order 13526 / DoDI 5200.01
  compliance with classification-based encryption policy enforcement.
- **Multi-protocol support** — HTTP/HTTPS, FTP/FTPS, SFTP/SCP, S3, Azure Blob,
  GCS, WebDAV, SMB, local filesystem, and DoD protocol handlers.
- **Plugin system** — dynamic protocol handler registration for custom schemes.
- **Parallel chunked transfers** — configurable parallel connections with
  range-based chunking for supported protocols.
- **Checksum verification** — SHA-256/SHA-512/MD5 integrity checking with
  automatic verification on download completion.
- **AFTP server** — TCP listener with TLS (rustls), challenge-response auth
  (HMAC-SHA256), rate limiting, and configurable root directory.
- **Multiplexed streams** — concurrent transfers over a single connection
  via STREAM_OPEN/CLOSE/DATA framing (reserved, not yet wired).
- **Telemetry** — opt-in anonymous usage telemetry with JSONL storage,
  remote sync, and full opt-out support.
- **Structured output** — JSON-formatted results for agentic workflow
  integration with `--agent` flag.
- **Audit logging** — structured audit events for compliance and monitoring.
- **Transfer history** — persistent JSONL history of all transfers.
- **TOML configuration** — file-based config with per-field override.
- **CLI** — clap-based interface with 12 subcommands: `get`, `put`, `copy`,
  `head`, `list`, `schema`, `capabilities`, `checksum`, `serve`, `plugin`,
  `crypto`, `telemetry`.
- **Export control documentation** — EAR ECCN 5D002 classification with
  License Exception ENC eligibility assessment and BIS notification draft.
- **271 tests** — comprehensive integration and unit tests covering engine,
  AFTP server, crypto roundtrips, CLI binary invocations, mux framing,
  classification, telemetry, error types, protocol resolution, plugins,
  ontology, output formatting, session resume, security hardening, and more.

### Changed

- License changed from MIT to AGPL-3.0-or-later with commercial licensing option.
- Error types: dedicated `AuthFailed` and `CryptoError` variants replace
  generic `PermissionDenied` / `Other` for auth and crypto failures.
- Engine: replaced fragile `.unwrap()` patterns with safe `matches!()` /
  `if let` destructuring.
- `lib.rs`: internal modules (`audit`, `cli`, `config`, `history`, `ontology`,
  `output`, `plugins`, `telemetry`) marked `#[doc(hidden)]`; public API
  restricted to `aftp`, `crypto`, `engine`, `error`, `protocols`.
- Dead code annotations reduced from 53 to 10 targeted `#[allow(dead_code)]`
  with explanatory comments on protocol-spec constants and public API fields.
- Clippy and `cargo doc` clean with zero warnings.

## [0.1.0] - 2024-12-01

### Added

- Initial release with core transfer engine and protocol framework.
