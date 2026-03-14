# AFT — Agentic File Transfer

**High-performance, protocol-agnostic file transfer CLI for humans and AI agents.**

AFT is designed from the ground up as an _agentic-first_ tool — every command produces structured, machine-readable output that AI agents can discover, parse, and act on. It also provides colorized, human-friendly output for interactive use.

## Features

- **Multi-protocol** — HTTP/HTTPS, FTP/FTPS, SFTP/SCP, S3, WebDAV, Azure Blob, GCS, SMB, AFTP/AFTPS, DoD CDS, local file system
- **AFTP — custom binary protocol** — 10-byte framed wire protocol with zstd compression,
  streaming SHA-256, TLS/mTLS, HMAC-SHA256 challenge/response auth, and TCP_NODELAY
- **Built-in file server** — `aft serve` exposes any directory over AFTP with optional
  TLS, authentication, and compression
- **Quantum-resistant encryption** — NIST FIPS 203 ML-KEM (Kyber1024) key encapsulation
  with AES-256-GCM authenticated encryption for post-quantum file protection
- **Neural network cipher** — Trainable MLP autoencoder encryption with OFB mode;
  custom models via `aft crypto train`, supports PQC, Neural, and Hybrid modes
- **DoD classification enforcement** — `dod://` protocol scheme with classification
  levels (CUI through Top Secret), STIG compliance, and X-Classification headers
- **Security hardened** — TLS 1.2+ enforcement, FIPS-compatible cipher suites, auth rate
  limiting, audit logging (`~/.aft/audit.log`), credential scrubbing, SMB path sanitization
- **DoD compliance audit** — SECURITY.md with CVE, MITRE ATT&CK, NIST FIPS 140-3, and
  CMMC 2.0 Level 2 assessment
- **Agentic ontology** — Self-describing `schema` and `capabilities` commands for
  automated tool discovery by AI agents
- **Structured output** — JSON output mode (`--agent` / `--format json`) with
  consistent schema across all operations
- **Parallel chunked downloads** — Multi-connection downloads for large files
  with HTTP byte-range support
- **Resume support** — Resume interrupted transfers with `--resume`
- **Retry with backoff** — Exponential backoff retry logic for reliability
- **Checksum verification** — SHA-256, SHA-512, and MD5 integrity verification
- **Recursive directory copy** — `aft copy -r` for directory trees across protocols
- **Bandwidth throttling** — `--rate-limit` to cap transfer speed in bytes/sec
- **Configuration file** — Persistent settings via `~/.aft/config.toml`
- **Transfer history** — Logged to `~/.aft/history.json` for auditing
- **Transport layers** — TCP (default), WebSocket, and QUIC transports for AFTP
- **Plugin system** — Load custom protocol handlers from shared libraries
- **Multiplexed streams** — Concurrent transfers over a single AFTP connection
- **Cross-platform** — Windows, macOS, and Linux
- **8.3 MB binary** — LTO, stripped, single codegen unit, panic=abort

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
# Binary at target/release/aft (or aft.exe on Windows)
```

## Quick Start

### Download a file

```bash
aft get https://example.com/file.tar.gz
aft get https://example.com/file.tar.gz -o ./downloads/
```

### Upload a file

```bash
aft put ./report.pdf https://upload.example.com/files/
aft put ./data.json https://api.example.com/upload --method POST --content-type application/json
```

### Copy between locations

```bash
aft copy ./src/ ./backup/src/
aft copy -r ./project/ sftp://server/backups/project/
```

### Inspect a remote resource

```bash
aft head https://example.com/file.tar.gz
```

### List directory contents

```bash
aft ls ./my-directory/
aft ls aftp://server:2600/
```

### Compute a checksum

```bash
aft checksum ./file.tar.gz --algorithm sha256
```

### Download with integrity verification

```bash
aft get https://example.com/release.tar.gz \
  --checksum sha256 \
  --checksum-value e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Resume a partial download

```bash
aft get https://example.com/large.iso -o ./large.iso --resume
```

## AFTP — Custom Binary Protocol

AFTP is a purpose-built binary file transfer protocol with 10-byte frame headers
and 1 MB data frames, yielding 0.001% framing overhead.

### Start a server

```bash
# Basic — serve a directory on port 2600
aft serve ./files

# With TLS and authentication
aft serve ./files --tls-cert cert.pem --tls-key key.pem --auth-token SECRET

# With HMAC-SHA256 challenge/response auth
aft serve ./files --auth-token SECRET --auth-challenge

# With zstd compression
aft serve ./files --compression
```

### Client operations

```bash
# List files on an AFTP server
aft ls aftp://server:2600/

# Download a file
aft get aftp://server:2600/data.bin -o ./data.bin

# Upload a file
aft put ./report.pdf aftp://server:2600/report.pdf

# Inspect metadata
aft head aftp://server:2600/data.bin

# TLS-encrypted connection (aftps://)
aft ls aftps://server:2600/
```

### Server options

| Flag               | Default   | Description                                |
| ------------------ | --------- | ------------------------------------------ |
| `--port`           | `2600`    | TCP port to listen on                      |
| `--bind`           | `0.0.0.0` | Address to bind to                         |
| `--auth-token`     |           | Pre-shared authentication token            |
| `--auth-challenge` | `false`   | Use HMAC-SHA256 challenge/response auth    |
| `--compression`    | `false`   | Enable zstd compression for data frames    |
| `--tls-cert`       |           | TLS certificate PEM file (enables AFTPS)   |
| `--tls-key`        |           | TLS private key PEM file                   |
| `--transport`      | `tcp`     | Transport layer: `tcp`, `ws`, or `quic`    |
| `--rate-limit`     | `0`       | Max bandwidth in bytes/sec (0 = unlimited) |

## Agent Mode

AFT is designed for AI agent integration. Use `--agent` for optimal machine consumption:

```bash
# Structured JSON output, no progress bars, deterministic
aft --agent get https://example.com/data.json -o /tmp/data.json

# Discover capabilities programmatically
aft --agent capabilities

# Full ontology schema for tool registration
aft --agent schema
```

## Quantum-Resistant Encryption

AFT includes post-quantum cryptography (NIST FIPS 203 ML-KEM / Kyber1024) and a
trainable neural network cipher for experimental encryption workflows.

### Generate a PQC key pair

```bash
aft crypto keygen -o ./keys/
# Creates aft_public.key and aft_secret.key
```

### Encrypt / decrypt with PQC (Kyber1024 + AES-256-GCM)

```bash
aft crypto encrypt -i secret.pdf -o secret.enc --method pqc --key-file ./keys/aft_public.key
aft crypto decrypt -i secret.enc -o secret.pdf --key-file ./keys/aft_secret.key
```

### Train a neural network cipher model

```bash
aft crypto train --epochs 2000 --learning-rate 0.01 -o ./model/
# Creates aft_neural.model (~90 KB)
```

### Encrypt / decrypt with neural cipher (OFB mode)

```bash
aft crypto encrypt -i data.bin -o data.enc --method neural --key-file ./model/aft_neural.model
aft crypto decrypt -i data.enc -o data.bin --key-file ./model/aft_neural.model
```

### Hybrid mode (PQC key exchange + neural cipher)

```bash
aft crypto encrypt -i payload.tar -o payload.enc --method hybrid --key-file ./keys/aft_public.key
aft crypto decrypt -i payload.enc -o payload.tar --key-file ./keys/aft_secret.key
```

### DoD classified transfers

```bash
# Transfer with classification enforcement (dod://LEVEL@host/path)
aft get dod://secret@server.mil/reports/sitrep.pdf -o ./sitrep.pdf
aft put ./intel.pdf dod://topsecret@server.mil/uploads/intel.pdf
```

### Output Schema

All operations return a consistent JSON structure:

```json
{
  "status": "success",
  "operation": "Download",
  "source": "https://example.com/file.tar.gz",
  "destination": "./file.tar.gz",
  "protocol": "https",
  "transfer": {
    "bytes_transferred": 10485760,
    "duration_ms": 2340,
    "throughput_bytes_per_sec": 4481523.0,
    "checksum": null,
    "retries_used": 0,
    "chunks_used": 4
  },
  "timestamp": "2026-03-13T12:00:00.000Z"
}
```

### Error Format

```json
{
  "status": "error",
  "operation": "Download",
  "source": "https://example.com/missing.txt",
  "error": "Server returned HTTP 404: Not Found",
  "timestamp": "2026-03-13T12:00:00.000Z"
}
```

## Plugin System

Extend AFT with custom protocol handlers via shared libraries:

```bash
# List loaded plugins
aft plugin list

# Load a plugin
aft plugin load ./my-protocol.dll

# Unload a plugin by scheme
aft plugin unload myproto
```

Plugins are automatically loaded from `~/.aft/plugins/` at startup.

## Security

AFT includes security features designed for DoD and enterprise environments.
See [SECURITY.md](SECURITY.md) for the full audit report covering CVE patterns,
MITRE ATT&CK mitigations, NIST FIPS 140-3 compliance, and CMMC 2.0 Level 2 assessment.

### Key Security Features

- **TLS 1.2+ enforced** — Only FIPS-compatible cipher suites (AES-256-GCM, AES-128-GCM with ECDHE)
- **Auth rate limiting** — Per-IP failure tracking with automatic 60-second lockout after 5 failures
- **Audit logging** — Structured JSON Lines audit trail at `~/.aft/audit.log` for SIEM integration
- **HMAC-SHA256 challenge/response** — Auth tokens never traverse the wire in challenge mode
- **Path traversal protection** — Multi-layer defense (string check + canonicalize + prefix verify)
- **Credential scrubbing** — `user:password@` and sensitive query params stripped from logs
- **SMB path sanitization** — Shell metacharacters rejected to prevent command injection
- **Memory safety** — Rust eliminates buffer overflows, use-after-free, and data races
- **Insecure mode warnings** — Prominent stderr alerts when `--insecure` bypasses certificate verification

### Supported Protocols

| Scheme                | Protocol             | Ranges | Resume | Auth                  |
| --------------------- | -------------------- | ------ | ------ | --------------------- |
| `http://`, `https://` | HTTP/HTTPS           | Yes    | Yes    | Bearer, Basic         |
| `ftp://`, `ftps://`   | FTP/FTPS             | Yes    | Yes    | Username/Password     |
| `sftp://`, `scp://`   | SFTP/SCP             | No     | No     | Key, Password         |
| `s3://`               | Amazon S3            | Yes    | Yes    | AWS credentials       |
| `aftp://`, `aftps://` | AFTP (custom)        | Yes    | Yes    | Token, HMAC challenge |
| `webdav://`, `dav://` | WebDAV               | Yes    | Yes    | Bearer, Basic         |
| `az://`, `azblob://`  | Azure Blob Storage   | Yes    | Yes    | Shared Key, SAS       |
| `gs://`               | Google Cloud Storage | Yes    | Yes    | Bearer token          |
| `smb://`              | SMB/CIFS             | No     | No     | UNC, smbclient        |
| `dod://`              | DoD CDS (HTTPS)      | Yes    | Yes    | Classification header |
| `file://`, paths      | Local filesystem     | Yes    | Yes    | OS permissions        |

## Global Options

| Flag                | Short | Default | Description                                |
| ------------------- | ----- | ------- | ------------------------------------------ |
| `--format`          | `-f`  | `text`  | Output format: `text`, `json`, `quiet`     |
| `--agent`           |       | `false` | Agent mode (JSON, no interactive elements) |
| `--parallel`        |       | `4`     | Parallel connections for chunked transfers |
| `--retries`         |       | `3`     | Max retry attempts                         |
| `--retry-delay-ms`  |       | `1000`  | Initial retry delay (exponential backoff)  |
| `--connect-timeout` |       | `30`    | Connection timeout (seconds)               |
| `--timeout`         |       | `0`     | Transfer timeout, 0 = unlimited (seconds)  |
| `--insecure`        |       | `false` | Skip TLS certificate verification          |
| `--rate-limit`      |       | `0`     | Max bandwidth in bytes/sec (0 = unlimited) |
| `--verbose`         | `-v`  | `false` | Verbose output                             |
| `--quiet`           | `-q`  | `false` | Suppress non-error output                  |

## Architecture

```
src/
├── main.rs              Entry point, command dispatch, UTF-8 console init
├── cli.rs               CLI parser (clap derive, 11 subcommands)
├── error.rs             Error types (AftError enum, thiserror)
├── engine.rs            Transfer engine (parallel chunks, retry, checksums)
├── output.rs            Structured + colorized output formatting
├── ontology.rs          Agentic JSON-LD ontology schema
├── config.rs            Configuration file (~/.aft/config.toml)
├── history.rs           Transfer history logging (~/.aft/history.json)
├── audit.rs             Security audit logging (~/.aft/audit.log, JSON Lines)
├── plugins.rs           Plugin system for custom protocol handlers
├── lib.rs               Library re-exports for testing
├── aftp/
│   ├── mod.rs           Module declarations
│   ├── frame.rs         AFTP binary wire protocol (19 frame types)
│   ├── server.rs        AFTP file server (TLS + challenge auth + rate limiting)
│   ├── client.rs        AFTP client (TLS + hardened cipher suites)
│   ├── mux.rs           Multiplexed streams over AFTP
│   └── transport.rs     Transport abstraction (TCP, WebSocket, QUIC)
├── crypto/
│   ├── mod.rs           Encryption pipeline (PQC, Neural, Hybrid), AFTE file format
│   ├── pqc.rs           Post-quantum crypto (ML-KEM Kyber1024 + AES-256-GCM)
│   ├── neural.rs        Trainable neural network cipher (MLP, OFB mode)
│   └── classification.rs DoD classification levels (CUI through Top Secret)
└── protocols/
    ├── mod.rs           ProtocolHandler trait + URL resolver (18 schemes)
    ├── http.rs          HTTP/HTTPS (reqwest)
    ├── local.rs         Local filesystem (256 KB buffers)
    ├── aftp.rs          AFTP/AFTPS adapter
    ├── ftp.rs           FTP/FTPS (suppaftp)
    ├── sftp.rs          SFTP/SCP (russh)
    ├── s3.rs            S3 (rust-s3)
    ├── webdav.rs        WebDAV/WebDAVS (PROPFIND, ranges)
    ├── azure_blob.rs    Azure Blob Storage (REST API)
    ├── gcs.rs           Google Cloud Storage (JSON API)
    ├── smb.rs           SMB/CIFS (UNC + smbclient)
    └── dod.rs           DoD CDS protocol (classification-aware HTTPS)

tests/
└── integration_tests.rs   131 tests (protocols, security, crypto, neural, classification, DoD)
```

### Protocol Abstraction

Every protocol implements `ProtocolHandler`:

```rust
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    fn scheme(&self) -> &str;
    fn name(&self) -> &str;
    fn supports_ranges(&self) -> bool;
    fn supports_resume(&self) -> bool;

    async fn head(&self, url: &str, opts: &ProtocolOptions) -> AftResult<ResourceMetadata>;
    async fn download(&self, url: &str, dest: &Path, opts: &ProtocolOptions, ...) -> AftResult<u64>;
    async fn download_range(&self, url: &str, start: u64, end: u64, opts: &ProtocolOptions) -> AftResult<Vec<u8>>;
    async fn upload(&self, source: &Path, url: &str, opts: &ProtocolOptions, ...) -> AftResult<u64>;
    async fn list(&self, url: &str, opts: &ProtocolOptions) -> AftResult<Vec<DirectoryEntry>>;
}
```

### Transfer Engine

- **Parallel chunked downloads** — Splits large files into chunks downloaded
  concurrently via HTTP byte ranges, then assembled into the output file
- **Exponential backoff retry** — Configurable retry count and initial delay
- **Resume** — Detects existing partial files and resumes from the last byte
- **Checksum verification** — SHA-256, SHA-512, MD5 post-transfer verification
- **Bandwidth throttling** — Token-bucket rate limiter for transfers

### Performance

- **Async I/O** — Built on Tokio for non-blocking I/O across all operations
- **Streaming** — Data streams directly to disk without full buffering
- **256 KB I/O buffers** — Tuned buffer sizes for local file operations
- **1 MB AFTP frames** — 0.001% framing overhead at maximum frame size
- **Connection pooling** — reqwest's built-in pool for HTTP
- **Release profile** — LTO, single codegen unit, stripped, panic=abort (8.3 MB)

## License

MIT
