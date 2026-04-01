# Changelog

All notable changes to AFT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-25

### Added

- **Sync engine** — rsync/rclone-class directory synchronization via `aft sync`
  with configurable compare modes (size, modtime, checksum), `--dry-run` preview,
  `--delete` extraneous files, include/exclude glob filters, size filters, and
  depth limiting.
- **Move command** — `aft mv` for moving/renaming files across protocols.
- **Remove command** — `aft rm` for deleting files and directories with optional
  `--recursive` flag.
- **Mkdir command** — `aft mkdir` for creating directories on any protocol.
- **Extended protocol operations** — `ProtocolHandler` trait extended with 7 new
  default methods: `supports_extended_ops()`, `delete()`, `rename()`,
  `mkdir()`, `set_timestamps()`, `exists()`, and `list_recursive()`.
  Full implementations on local filesystem; other protocols inherit safe defaults.
- **DirectoryEntry metadata** — `relative_path`, `is_symlink`, and
  `permissions` fields for richer directory listings.
- **Recursive listing** — `aft ls -r` with depth-limited BFS traversal.
- **Long listing format** — `aft ls -l` for detailed directory output.
- **Preserve timestamps** — `--preserve` flag on `aft copy`.
- **Include/exclude filters** — `--include` and `--exclude` glob patterns on
  `aft copy` and `aft sync`.
- **Dry-run mode** — `--dry-run` on copy and sync to preview operations.
- **314 tests** — 43 new tests covering sync engine, extended protocol operations,
  and new CLI subcommands.

### Changed

- CLI expanded from 12 to 16 subcommands.
- `OutputResult` gains an optional `extra` field for structured sync results.
## [1.1.0] - 2026-03-24

### Added

- **Hardware-accelerated CRC32 per-frame integrity** — optional CRC32 trailer on
  DATA frames using `crc32fast` (SSE4.2 / ARM CRC32 hardware instructions when
  available). Negotiated via `CAP_CRC32_FRAMES` capability in the HELLO handshake.
- **Deployment Modes documentation** — README section covering local-only,
  air-gapped, hardware-accelerated, sandboxed, and plugin deployment topologies.

### Changed

- **XOR widening** — Hybrid crypto XOR step widened from byte-at-a-time to
  `u64`-chunked processing via `xor_with_key()` for ~8× fewer loop iterations.
- **TLS hardened** — minimum TLS 1.2 enforced; cipher suites restricted to
  FIPS-compatible AES-256-GCM and AES-128-GCM with ECDHE key exchange.
- **Auth rate limiting** — per-IP failure tracking with automatic 60-second
  lockout after 5 consecutive failures.
- **Credential scrubbing** — `user:password@` and sensitive query parameters
  stripped from all log output.
- **SMB path sanitization** — shell metacharacters rejected to prevent command
  injection in SMB paths.

### Fixed

- Resolved `cargo audit` advisories for `aws-lc-sys` (RUSTSEC-2024-0425) and
  `rustls-webpki` (RUSTSEC-2025-0013) via dependency updates.

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
