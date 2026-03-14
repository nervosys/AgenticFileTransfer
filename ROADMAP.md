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

---

## Current Counts

- **Done:** 53
- **Planned:** 0

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
├── history.rs             # Transfer history logging (~/.aft/history.json)
├── audit.rs               # Security audit logging (~/.aft/audit.log, JSON Lines)
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
└── integration_tests.rs   # 131 tests (protocols, security, crypto, neural, classification, DoD)
```
