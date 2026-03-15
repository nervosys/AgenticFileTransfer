# AFT Roadmap

Implementation progress for **AFT (Agentic File Transfer)** — a high-performance,
protocol-agnostic file transfer CLI for humans and AI agents.

---

## Phase 1: Core Architecture & CLI

| #   | Task                                                                             | Status |
| --- | -------------------------------------------------------------------------------- | ------ |
| 1   | Project scaffolding (Cargo.toml, .gitignore, README)                             | Done   |
| 2   | Error types (`src/error.rs` — `AftError` enum with `thiserror`)                  | Done   |
| 3   | CLI parser (`src/cli.rs` — clap derive with 9 subcommands)                       | Done   |
| 4   | Protocol abstraction trait (`src/protocols/mod.rs` — `ProtocolHandler`)          | Done   |
| 5   | Structured output module (`src/output.rs` — text/json/quiet formats)             | Done   |
| 6   | Agentic ontology schema (`src/ontology.rs` — JSON-LD, `schema` + `capabilities`) | Done   |
| 7   | Transfer engine (`src/engine.rs` — parallel chunks, retry, checksums)            | Done   |
| 8   | Main entry point & command dispatch (`src/main.rs`)                              | Done   |

## Phase 2: Protocol Handlers

| #   | Task                                                                              | Status |
| --- | --------------------------------------------------------------------------------- | ------ |
| 9   | HTTP/HTTPS handler (`src/protocols/http.rs` — reqwest, streaming, ranges)         | Done   |
| 10  | Local filesystem handler (`src/protocols/local.rs` — 256 KB buffers, seek resume) | Done   |
| 11  | FTP/FTPS handler (`src/protocols/ftp.rs`)                                         | Done   |
| 12  | SFTP/SCP handler (`src/protocols/sftp.rs`)                                        | Done   |
| 13  | S3 handler (`src/protocols/s3.rs`)                                                | Done   |

## Phase 3: AFTP — Custom Binary Protocol

| #   | Task                                                                        | Status |
| --- | --------------------------------------------------------------------------- | ------ |
| 14  | Binary wire protocol (`src/aftp/frame.rs` — 10-byte headers, 1 MB frames)   | Done   |
| 15  | AFTP server (`src/aftp/server.rs` — zstd, streaming SHA-256, TCP_NODELAY)   | Done   |
| 16  | AFTP client (`src/aftp/client.rs` — HELLO handshake, all operations)        | Done   |
| 17  | Protocol handler adapter (`src/protocols/aftp.rs` — `ProtocolHandler` impl) | Done   |
| 18  | `serve` CLI subcommand                                                      | Done   |

## Phase 4: Hardening & Polish

| #   | Task                                                                 | Status |
| --- | -------------------------------------------------------------------- | ------ |
| 19  | Windows console UTF-8 encoding fix (`SetConsoleOutputCP`)            | Done   |
| 20  | ASCII-safe terminal output (replaced Unicode glyphs)                 | Done   |
| 21  | End-to-end AFTP testing (ls, head, get, put)                         | Done   |
| 22  | Release build optimization (LTO, strip, panic=abort — 8.3 MB binary) | Done   |

## Phase 5: Protocol Completions

| #   | Task                                                    | Status |
| --- | ------------------------------------------------------- | ------ |
| 23  | FTP/FTPS — full implementation (suppaftp, async-rustls) | Done   |
| 24  | SFTP/SCP — full implementation (russh + russh-sftp)     | Done   |
| 25  | S3 — full implementation (rust-s3, tokio-rustls-tls)    | Done   |

## Phase 6: Advanced Features

| #   | Task                                                           | Status |
| --- | -------------------------------------------------------------- | ------ |
| 26  | TLS/mTLS for AFTP connections (tokio-rustls + webpki-roots)    | Done   |
| 27  | AFTP authentication (token + challenge/response)               | Done   |
| 28  | AFTP multiplexed streams (concurrent transfers per connection) | Done   |
| 29  | Recursive directory copy/sync                                  | Done   |
| 30  | Bandwidth throttling / rate limiting                           | Done   |
| 31  | Configuration file support (~/.aft/config.toml)                | Done   |
| 32  | Transfer logging & history (~/.aft/history.json)               | Done   |
| 33  | WebSocket/QUIC transport layer                                 | Done   |
| 34  | Plugin system for custom protocol handlers                     | Done   |
| 35  | Comprehensive test suite (90 tests — unit + integration)       | Done   |

## Phase 7: Additional Protocols

| #   | Task                                                                  | Status |
| --- | --------------------------------------------------------------------- | ------ |
| 36  | WebDAV handler (`src/protocols/webdav.rs` — PROPFIND, ranges, resume) | Done   |
| 37  | Azure Blob Storage handler (`src/protocols/azure_blob.rs` — REST API) | Done   |
| 38  | Google Cloud Storage handler (`src/protocols/gcs.rs` — JSON API)      | Done   |
| 39  | SMB/CIFS handler (`src/protocols/smb.rs` — UNC + smbclient fallback)  | Done   |

## Phase 8: Security Hardening & DoD Compliance

| #   | Task                                                                         | Status |
| --- | ---------------------------------------------------------------------------- | ------ |
| 40  | SECURITY.md — CVE, MITRE ATT&CK, NIST FIPS 140-3, CMMC 2.0 audit             | Done   |
| 41  | TLS hardening — enforce TLS 1.2+, FIPS cipher suites only                    | Done   |
| 42  | Auth rate limiting — per-IP failure tracking with lockout                    | Done   |
| 43  | Audit logging subsystem (`src/audit.rs` — JSON Lines, SIEM-ready)            | Done   |
| 44  | Insecure mode warnings — prominent stderr alerts for `--insecure`            | Done   |
| 45  | SMB path sanitization — reject shell metacharacters in smbclient paths       | Done   |
| 46  | Credential scrubbing — strip user:pass@ and sensitive query params from logs | Done   |
| 47  | Expanded test suite (108 tests — new protocols, security, audit)             | Done   |

## Phase 9: Quantum-Resistant Encryption & DoD Protocols

| #   | Task                                                                                 | Status |
| --- | ------------------------------------------------------------------------------------ | ------ |
| 48  | Post-quantum crypto module (`src/crypto/pqc.rs` — ML-KEM Kyber1024 + AES-256-GCM)    | Done   |
| 49  | Neural network encoder-decoder cipher (`src/crypto/neural.rs` — trainable, OFB mode) | Done   |
| 50  | DoD classification system (`src/crypto/classification.rs` — CUI through Top Secret)  | Done   |
| 51  | DoD CDS protocol handler (`src/protocols/dod.rs` — classification-aware HTTPS)       | Done   |
| 52  | Crypto CLI subcommand (`aft crypto keygen/train/encrypt/decrypt`)                    | Done   |
| 53  | Expanded test suite (131 tests — crypto, neural, classification, DoD protocol)       | Done   |

## Phase 10: Hardening, Performance & CI/CD

| #   | Task                                                                                 | Status |
| --- | ------------------------------------------------------------------------------------ | ------ |
| 54  | Plugin signature verification (SHA-256 sidecar `.sha256` files)                      | Done   |
| 55  | FIPS 140-3 crypto backend feature flag (`--features fips` → aws-lc-rs provider)      | Done   |
| 56  | SMB control character injection hardening (reject ASCII 0-31, 127, C1 U+0080-U+009F) | Done   |
| 57  | Audit logging for HEAD and LIST operations on AFTP server                            | Done   |
| 58  | `--insecure` stderr warning + audit event (`InsecureMode`)                           | Done   |
| 59  | Neural training `spawn_blocking` (prevent async runtime blocking)                    | Done   |
| 60  | History file: append-only JSON Lines format (`history.jsonl`, O(1) writes)           | Done   |
| 61  | Commit Cargo.lock for reproducible builds                                            | Done   |
| 62  | Fix `decrypt_block` dead code warning                                                | Done   |
| 63  | Crate-level and module doc comments for public APIs                                  | Done   |
| 64  | Remove `.expect()` / `.unwrap()` from QUIC transport code                            | Done   |
| 65  | CI pipeline (GitHub Actions: test, clippy, fmt, security audit)                      | Done   |
| 66  | MSRV policy (`rust-version = "1.75"` in Cargo.toml)                                  | Done   |
| 67  | Streaming checksum verification (64 KB buffered reads, no full-file load)            | Done   |

## Phase 11: Quality, Testing & CI Hardening

| #   | Task                                                                                  | Status |
| --- | ------------------------------------------------------------------------------------- | ------ |
| 68  | End-to-end AFTP server integration tests (start/GET/PUT/LIST/HEAD)                    | Done   |
| 69  | Security-specific tests (path traversal, rate limiting, malicious frames)             | Done   |
| 70  | Crypto roundtrip file-level tests (PQC, Neural, Hybrid encrypt→decrypt)               | Done   |
| 71  | CI: MSRV (1.75) verification job                                                      | Done   |
| 72  | CI: FIPS feature flag build verification                                              | Done   |
| 73  | CI: Release build verification                                                        | Done   |
| 74  | CI: cargo-deny supply chain audit                                                     | Done   |
| 75  | Server connection limit (`--max-connections` + semaphore)                             | Done   |
| 76  | Certificate pinning (`--pin-cert`) and CA bundle (`--ca-bundle`) CLI options          | Done   |
| 77  | Expand credential scrubbing (access_key, secret_key, api_key, bearer, oauth_token)    | Done   |
| 78  | Secure temp file permissions (mode 0o600 on Unix)                                     | Done   |
| 79  | Plugin init error reporting (log errors in verbose mode)                              | Done   |
| 80  | Streaming checksum in `cmd_checksum` (64 KB buffered reads)                           | Done   |
| 81  | Server `handle_connection` section comments (handshake/auth/negotiation/request loop) | Done   |
| 82  | SMB single-pass character validation (merged control + allowlist loops)               | Done   |
| 83  | FIPS 140-3 build documentation in README                                              | Done   |
| 84  | SECURITY.md quick assessment table (CUI/SECRET/TS/Internet suitability)               | Done   |

---

## Phase 12: Hardening & Defense-in-Depth

| #   | Task                                                                                 | Status |
| --- | ------------------------------------------------------------------------------------ | ------ |
| 85  | Hybrid crypto: replace `unwrap()` with safe error propagation on shared secret slice | Done   |
| 86  | AFTP server: 5-minute idle connection timeout (`tokio::time::timeout`)               | Done   |
| 87  | Wire `--pin-cert`/`--ca-bundle` into `ProtocolOptions` for downstream TLS use        | Done   |
| 88  | Max download size guard (100 GiB) prevents disk-exhaustion DoS in chunked downloads  | Done   |
| 89  | Config validation: reject `parallel=0`, `connect_timeout>3600`, `retries>100`        | Done   |
| 90  | Decrypt: validate `original_len` header field (reject > 1 TiB)                       | Done   |
| 91  | Temp file scope guard (RAII cleanup on panic) for cross-protocol copy                | Done   |
| 92  | URL scheme character validation (RFC 3986 compliance)                                | Done   |
| 93  | Rate limiter: automatic expiration cleanup when map exceeds 1000 entries             | Done   |
| 94  | Audit & history log file permissions restricted to 0o600 on Unix                     | Done   |
| 95  | Sanitize filesystem paths from plugin error messages (no path leaks)                 | Done   |
| 96  | Document transport.rs dead-code rationale (public API for future multi-transport)    | Done   |

---

## Phase 13: Remote Telemetry

| #   | Task                                                                         | Status |
| --- | ---------------------------------------------------------------------------- | ------ |
| 97  | TelemetryConfig struct with opt-in default, installation ID, remote endpoint | Done   |
| 98  | TelemetryRecord struct for structured event data (JSONL format)              | Done   |
| 99  | TelemetryStore with local JSONL persistence (~/.aft/telemetry_records.jsonl) | Done   |
| 100 | TelemetryCollector convenience wrapper for batching events                   | Done   |
| 101 | TelemetryEvent enum (commands, transfers, errors, app started)               | Done   |
| 102 | Remote sync to AWS EC2 endpoint (reqwest async POST /ingest)                 | Done   |
| 103 | CLI subcommand: `aft telemetry status`                                       | Done   |
| 104 | CLI subcommand: `aft telemetry opt-in` / `opt-out`                           | Done   |
| 105 | CLI subcommand: `aft telemetry reset` (regenerate installation ID)           | Done   |
| 106 | CLI subcommand: `aft telemetry sync` (manual remote upload)                  | Done   |
| 107 | CLI subcommand: `aft telemetry clear` / `export`                             | Done   |
| 108 | CLI subcommand: `aft telemetry config` (endpoint/api-key setup)              | Done   |
| 109 | Integration tests for telemetry config validation                            | Done   |

---

## Phase 14: Audit & Hardening

| #   | Task                                                                               | Status |
| --- | ---------------------------------------------------------------------------------- | ------ |
| 110 | Wire telemetry into command execution (track_command, track_transfer, track_error) | Done   |
| 111 | Fix ontology serialization unwrap() panics (graceful fallback)                     | Done   |
| 112 | Fix WebDAV PROPFIND unwrap() with documented expect()                              | Done   |
| 113 | Add recursion depth limit (MAX_COPY_DEPTH = 100) to recursive copy                 | Done   |
| 114 | Add crypto and telemetry operation schemas to ontology                             | Done   |
| 115 | Reject unsupported transports (ws/quic) in serve command                           | Done   |
| 116 | Fix progress bar template unwrap() with documented expect()                        | Done   |
| 117 | Warn on config file corruption instead of silent fallback                          | Done   |
| 118 | Fix DoD hardcoded range/resume support (conservative false default)                | Done   |
| 119 | Wire audit logging for server lifecycle (ServerStart, ServerStop)                  | Done   |

---

## Phase 15: Security Hardening II

| #   | Task                                                                               | Status |
| --- | ---------------------------------------------------------------------------------- | ------ |
| 120 | Fix empty URL scheme bypass (vacuous truth in RFC 3986 validation)                 | Done   |
| 121 | Fix chunked download fallback file corruption (truncate before retry)              | Done   |
| 122 | Fix chunk range integer overflow (saturating arithmetic)                            | Done   |
| 123 | Handle plugin registry mutex poisoning gracefully                                   | Done   |
| 124 | Check Windows SetConsoleOutputCP return code                                        | Done   |
| 125 | Warn on world-readable config file permissions (Unix)                               | Done   |
| 126 | Bound rate limiter HashMap (MAX_TRACKED_IPS = 10,000, aggressive cleanup)           | Done   |
| 127 | Sanitize server error messages (generic responses to clients)                       | Done   |
| 128 | Add neural model SHA-256 signature verification (.aftnn.sha256 sidecar)             | Done   |

---

## Current Counts

- **Done:** 128
- **Planned:** 0

## Known Issues & Security Debt

| Issue                                    | Severity | Notes                                                            |
| ---------------------------------------- | -------- | ---------------------------------------------------------------- |
| Neural cipher not formally audited       | Medium   | Experimental — not recommended for production classified         |
| Plugin system loads native code          | Medium   | Mitigated by SHA-256 signature verification                      |
| Neural model file integrity              | Low      | Mitigated by optional .aftnn.sha256 sidecar verification         |
| `--insecure` disables all TLS validation | Low      | Mitigated by stderr warning + audit event                        |
| `--pin-cert`/`--ca-bundle` in opts only  | Low      | Plumbed into ProtocolOptions; protocol handlers can now use them |

## Architecture

```shell
src/
├── main.rs                # Entry point, command dispatch, UTF-8 console init
├── cli.rs                 # CLI parser (clap derive, 9 subcommands)
├── error.rs               # Error types (AftError enum)
├── engine.rs              # Transfer engine (parallel chunks, retry, checksums)
├── output.rs              # Structured output (text/json/quiet)
├── ontology.rs            # Agentic JSON-LD ontology schema
├── config.rs              # Configuration file (~/.aft/config.toml)
├── history.rs             # Transfer history logging (~/.aft/history.jsonl, JSON Lines)
├── audit.rs               # Security audit logging (~/.aft/audit.log, JSON Lines)
├── telemetry.rs           # Remote telemetry (AWS EC2, opt-in default, JSONL)
├── lib.rs                 # Library re-exports for testing
├── plugins.rs             # Plugin system for custom protocol handlers
├── aftp/
│   ├── mod.rs             # Module declarations
│   ├── frame.rs           # AFTP binary wire protocol
│   ├── server.rs          # AFTP file server (TLS + challenge auth + rate limiting)
│   ├── client.rs          # AFTP client (TLS + hardened cipher suites)
│   ├── mux.rs             # Multiplexed streams over AFTP
│   └── transport.rs       # Transport abstraction (TCP, WebSocket, QUIC)
├── crypto/
│   ├── mod.rs             # Encryption pipeline (PQC, Neural, Hybrid), AFTE file format
│   ├── pqc.rs             # Post-quantum crypto (ML-KEM Kyber1024 + AES-256-GCM)
│   ├── neural.rs          # Trainable neural network cipher (MLP autoencoder, OFB mode)
│   └── classification.rs  # DoD classification levels (CUI through Top Secret)
└── protocols/
    ├── mod.rs             # ProtocolHandler trait + URL resolver (18 schemes)
    ├── http.rs            # HTTP/HTTPS
    ├── local.rs           # Local filesystem
    ├── aftp.rs            # AFTP/AFTPS adapter
    ├── ftp.rs             # FTP/FTPS (suppaftp)
    ├── sftp.rs            # SFTP/SCP (russh)
    ├── s3.rs              # S3 (rust-s3)
    ├── webdav.rs          # WebDAV/WebDAVS (PROPFIND, ranges)
    ├── azure_blob.rs      # Azure Blob Storage (REST API)
    ├── gcs.rs             # Google Cloud Storage (JSON API)
    ├── smb.rs             # SMB/CIFS (UNC + smbclient)
    └── dod.rs             # DoD CDS protocol (classification-aware HTTPS)
tests/
└── integration_tests.rs   # Integration & unit tests (protocols, security, crypto, neural, classification, DoD)
.github/
└── workflows/ci.yml       # CI pipeline (test, clippy, fmt, cargo-audit)
```
