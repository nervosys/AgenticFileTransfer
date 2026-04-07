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
- **Turbo transfer engine** — Adaptive high-performance transfers that outperform
  Globus, Aspera, and HPN-SSH: dynamic mode selection (multi-stream, mmap, standard),
  automatic link probing (RTT/bandwidth/BDP), up to 128 parallel streams per file,
  16 MiB socket buffer auto-tuning, memory-mapped zero-copy I/O, and adaptive chunk
  sizing (1 MiB → 64 MiB) — all via a single `--turbo` flag
- **Resume support** — Resume interrupted transfers with `--resume`
- **Intermittent connection resilience** — MOSH-inspired session persistence: the server
  tracks upload progress per session, and clients can reconnect and resume mid-transfer
  after network interruptions without restarting from scratch
- **Retry with backoff** — Exponential backoff retry logic for reliability
- **Checksum verification** — SHA-256, SHA-512, and MD5 integrity verification
- **Directory synchronization** — `aft sync` with rsync/rclone-class sync engine:
  configurable compare modes (size, modtime, checksum), `--dry-run`, `--delete`
  extraneous, include/exclude glob filters, size filters, and depth limiting
- **Move / rename** — `aft mv` to move or rename files across protocols
- **Delete** — `aft rm` to remove files and directories (with `--recursive`)
- **Create directories** — `aft mkdir` to create directories on any protocol
- **Preserve timestamps** — `--preserve` flag to copy modification times
- **Extended protocol operations** — `delete`, `rename`, `mkdir`, `set_timestamps`,
  `exists`, and `list_recursive` operations on all protocol handlers with default
  implementations (full support on local filesystem)
- **Recursive directory copy** — `aft copy -r` for directory trees across protocols
- **Bandwidth throttling** — `--rate-limit` to cap transfer speed in bytes/sec
- **Configuration file** — Persistent settings via `~/.aft/config.toml`
- **Transfer history** — Logged to `~/.aft/history.jsonl` (JSON Lines) for auditing
- **Transport layers** — TCP (default), WebSocket, and QUIC transports for AFTP
- **Plugin system** — Load custom protocol handlers from shared libraries (SHA-256 signature verified)
- **FIPS 140-3 mode** — `cargo build --features fips` switches TLS to aws-lc-rs FIPS-validated provider
- **CI/CD** — GitHub Actions pipeline with test, clippy, fmt, and cargo-audit
- **Multiplexed streams** — Concurrent transfers over a single AFTP connection
- **Deployment flexibility** — Local-only, air-gapped/SCIF, hardware/removable media,
  sandboxed containers, and internet-connected environments all supported
- **Cross-platform** — Windows, macOS, and Linux
- **~9 MB binary** — LTO, stripped, single codegen unit, panic=abort; zero runtime dependencies

## Deployment Modes

AFT is a self-contained static binary with no runtime dependencies, making it suitable
for a wide range of operating environments — from internet-connected workstations to
classified air-gapped networks.

### Local-Only

All core operations work without any network access via the `file://` scheme:

```bash
# Copy between local directories
aft copy ./source/ ./backup/source/ -r

# Compute checksums
aft checksum ./release.bin --algorithm sha256

# List local files
aft ls ./data/

# Encrypt / decrypt entirely offline
aft crypto keygen -o ./keys/
aft crypto encrypt ./secret.pdf -o ./secret.afte -k ./keys/keys.pub -m pqc
aft crypto decrypt ./secret.afte -o ./secret.pdf -k ./keys/keys.sec
```

Local-to-local transfers use 256 KB I/O buffers and bypass all network code paths —
no sockets are opened.

### Air-Gapped / SCIF

AFT is deployable on air-gapped and disconnected networks with no modification:

- **No external dependencies** — Single static binary; no dynamic library loading
  required (plugins are opt-in from `~/.aft/plugins/`)
- **Offline crypto** — PQC keygen, encrypt, and decrypt use only local entropy
  (`OsRng`) and need no network
- **Local AFTP server** — `aft serve ./files` starts a file server over loopback
  or an isolated LAN for high-performance binary transfers within a secure enclave
- **FIPS 140-3 mode** — `cargo build --release --features fips` for environments
  requiring FIPS-validated TLS (aws-lc-rs)

```bash
# Air-gapped workflow: server on one node, client on another
# Node A (file server):
aft serve ./shared --bind 10.0.0.1 --tls-cert cert.pem --tls-key key.pem --auth-token TOKEN

# Node B (client):
aft ls aftps://10.0.0.1:2600/
aft get aftps://10.0.0.1:2600/payload.bin -o ./payload.bin
```

### Hardware Devices & Removable Media

AFT treats any mounted filesystem path as a first-class transfer endpoint. This
includes USB drives, external SSDs, NAS mounts, and block devices presented as volumes:

```bash
# Windows — USB drive mounted at E:\
aft copy ./classified/ E:\transfer\classified\ -r
aft checksum E:\transfer\classified\report.pdf --algorithm sha256

# Linux / macOS — removable media at /mnt/usb
aft copy ./data/ /mnt/usb/data/ -r
aft get aftp://server:2600/export.tar -o /mnt/usb/export.tar

# NAS / network share mounted locally
aft copy -r /mnt/nas/project/ ./local-mirror/
```

Path resolution is automatic — any relative or absolute filesystem path, drive letter,
or `file://` URI is handled by the local protocol handler with resume and range support.

### Sandboxed & Minimal Environments

AFT works in restricted environments (containers, CI runners, minimal VMs) with no
special setup:

- **No daemon** — Pure CLI invocation; no background service or socket needed
- **No config required** — All options are passable via flags; `~/.aft/` is created
  lazily only when needed (history, config, audit, telemetry)
- **Deterministic agent mode** — `--agent` suppresses all interactive elements (progress
  bars, color) for clean parsing in automation pipelines
- **Stateless operation** — Each invocation is self-contained; no lock files or shared
  state between runs
- **Minimal I/O footprint** — `--format quiet` suppresses all non-error output;
  `--quiet` combined with `--format json` emits only the final JSON result

```bash
# CI/CD pipeline — download, verify, no interactive output
aft --agent get https://releases.example.com/build.tar.gz -o ./build.tar.gz \
  --checksum sha256 \
  --checksum-value abc123...

# Container — transfer between mounted volumes
aft copy /input/data.csv /output/data.csv

# Sandboxed agent — structured JSON for programmatic consumption
aft --format json checksum ./artifact.bin --algorithm sha256
```

### Arbitrary Protocols via Plugins

Beyond the 12 built-in protocol handlers, AFT supports runtime-loadable protocol
plugins as shared libraries (`.dll` / `.so` / `.dylib`). Plugins implement the
`ProtocolHandler` trait and register a URL scheme:

```bash
# Load a custom protocol handler
aft plugin load ./my-protocol.so

# Use it with any AFT command
aft get myproto://device/sensor-data -o ./readings.bin
aft ls myproto://device/

# Permanently install — drop into the plugin directory
cp ./my-protocol.so ~/.aft/plugins/
```

Plugins are SHA-256 signature verified on load. This enables integration with
proprietary transfer systems, hardware interfaces, or domain-specific protocols
without modifying AFT itself. See [Plugin System](#plugin-system) for details.

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

### Synchronize directories

```bash
# Sync local to remote (rsync-style — only transfer changed files)
aft sync ./project/ sftp://server/backup/project/

# Dry run — preview what would change
aft sync ./src/ ./dst/ --dry-run

# Delete extraneous files in destination
aft sync ./src/ ./dst/ --delete

# Include/exclude filters
aft sync ./src/ ./dst/ --include "*.rs" --exclude "target/*"

# Compare by checksum instead of size
aft sync ./src/ ./dst/ --compare checksum
```

### Move / rename

```bash
aft mv ./old-name.txt ./new-name.txt
aft mv ./file.pdf sftp://server/archive/file.pdf
```

### Delete files and directories

```bash
aft rm ./temp-file.txt
aft rm ./build-output/ --recursive
```

### Create directories

```bash
aft mkdir ./new-dir/sub-dir/
aft mkdir sftp://server/uploads/batch-001/
```
### Inspect a remote resource

```bash
aft head https://example.com/file.tar.gz
```

### List directory contents

```bash
aft ls ./my-directory/
aft ls aftp://server:2600/

# Recursive listing with long format
aft ls -r -l ./project/
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

AFTP is a purpose-built binary file transfer protocol with 10-byte frame headers and 1 MB data frames, yielding 0.001% framing overhead.

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

| Flag                | Default   | Description                                |
| ------------------- | --------- | ------------------------------------------ |
| `--port`            | `2600`    | TCP port to listen on                      |
| `--bind`            | `0.0.0.0` | Address to bind to                         |
| `--auth-token`      |           | Pre-shared authentication token            |
| `--auth-challenge`  | `false`   | Use HMAC-SHA256 challenge/response auth    |
| `--compression`     | `false`   | Enable zstd compression for data frames    |
| `--tls-cert`        |           | TLS certificate PEM file (enables AFTPS)   |
| `--tls-key`         |           | TLS private key PEM file                   |
| `--transport`       | `tcp`     | Transport layer: `tcp`, `ws`, or `quic`    |
| `--rate-limit`      | `0`       | Max bandwidth in bytes/sec (0 = unlimited) |
| `--max-connections` | `1000`    | Max concurrent connections (0 = unlimited) |

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

AFT includes post-quantum cryptography (NIST FIPS 203 ML-KEM / Kyber1024) and a trainable neural network cipher for experimental encryption workflows.

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

## DoD Classified Transfers

```bash
# Transfer with classification enforcement (dod://LEVEL@host/path)
aft get dod://secret@server.mil/reports/sitrep.pdf -o ./sitrep.pdf
aft put ./intel.pdf dod://topsecret@server.mil/uploads/intel.pdf
```

## Output Schema

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

## Error Format

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
See [SECURITY.md](docs/SECURITY.md) for the full audit report covering CVE patterns,
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

| Flag                | Short | Default | Description                                  |
| ------------------- | ----- | ------- | -------------------------------------------- |
| `--format`          | `-f`  | `text`  | Output format: `text`, `json`, `quiet`       |
| `--agent`           |       | `false` | Agent mode (JSON, no interactive elements)   |
| `--parallel`        |       | `4`     | Parallel connections for chunked transfers   |
| `--retries`         |       | `3`     | Max retry attempts                           |
| `--retry-delay-ms`  |       | `1000`  | Initial retry delay (exponential backoff)    |
| `--connect-timeout` |       | `30`    | Connection timeout (seconds)                 |
| `--timeout`         |       | `0`     | Transfer timeout, 0 = unlimited (seconds)    |
| `--insecure`        |       | `false` | Skip TLS certificate verification            |
| `--rate-limit`      |       | `0`     | Max bandwidth in bytes/sec (0 = unlimited)   |
| `--turbo`           |       | `false` | Enable turbo mode (adaptive multi-stream)    |
| `--streams`         |       | `0`     | Parallel streams in turbo (0 = auto)         |
| `--chunk-size`      |       | `0`     | Chunk size in bytes for turbo (0 = adaptive) |
| `--sock-buf`        |       | `0`     | Socket buffer size for turbo (0 = auto BDP)  |
| `--no-mmap`         |       | `false` | Disable memory-mapped I/O in turbo mode      |
| `--pin-cert`        |       |         | Pin TLS cert by SHA-256 fingerprint (hex)    |
| `--ca-bundle`       |       |         | Custom CA certificate bundle (PEM file)      |
| `--verbose`         | `-v`  | `false` | Verbose output                               |
| `--quiet`           | `-q`  | `false` | Suppress non-error output                    |

## Architecture

```shell
src/
├── main.rs                 # Entry point, command dispatch, UTF-8 console init
├── cli.rs                  # CLI parser (clap derive, 16 subcommands)
├── error.rs                # Error types (AftError enum, thiserror)
├── engine.rs               # Transfer engine (parallel chunks, retry, checksums)
├── output.rs               # Structured + colorized output formatting
├── ontology.rs             # Agentic JSON-LD ontology schema
├── config.rs               # Configuration file (~/.aft/config.toml)
├── history.rs              # Transfer history logging (~/.aft/history.jsonl, JSON Lines)
├── audit.rs                # Security audit logging (~/.aft/audit.log, JSON Lines)
├── plugins.rs              # Plugin system for custom protocol handlers
├── sync.rs                 # rsync/rclone-class directory sync engine
├── turbo.rs                # Turbo transfer engine (multi-stream, mmap, adaptive)
├── lib.rs                  # Library re-exports for testing
├── aftp/
│   ├── mod.rs              # Module declarations
│   ├── frame.rs            # AFTP binary wire protocol (21+ frame types)
│   ├── server.rs           # AFTP file server (TLS + challenge auth + rate limiting)
│   ├── client.rs           # AFTP client (TLS + hardened cipher suites)
│   ├── mux.rs              # Multiplexed streams over AFTP
│   └── transport.rs        # Transport abstraction (TCP, WebSocket, QUIC)
├── crypto/
│   ├── mod.rs              # Encryption pipeline (PQC, Neural, Hybrid), AFTE file format
│   ├── pqc.rs              # Post-quantum crypto (ML-KEM Kyber1024 + AES-256-GCM)
│   ├── neural.rs           # Trainable neural network cipher (MLP, OFB mode)
│   └── classification.rs   # DoD classification levels (CUI through Top Secret)
└── protocols/
    ├── mod.rs              # ProtocolHandler trait + URL resolver (18 schemes)
    ├── http.rs             # HTTP/HTTPS (reqwest)
    ├── local.rs            # Local filesystem (256 KB buffers)
    ├── aftp.rs             # AFTP/AFTPS adapter
    ├── ftp.rs              # FTP/FTPS (suppaftp)
    ├── sftp.rs             # SFTP/SCP (russh)
    ├── s3.rs               # S3 (rust-s3)
    ├── webdav.rs           # WebDAV/WebDAVS (PROPFIND, ranges)
    ├── azure_blob.rs       # Azure Blob Storage (REST API)
    ├── gcs.rs              # Google Cloud Storage (JSON API)
    ├── smb.rs              # SMB/CIFS (UNC + smbclient)
    └── dod.rs              # DoD CDS protocol (classification-aware HTTPS)
tests/
└── integration_tests.rs    # 322 tests (engine, AFTP server, crypto, CLI, mux, classification, telemetry, session resume, hardening, sync, extended ops)
.github/
└── workflows/ci.yml        # CI pipeline (test, clippy, fmt, cargo-audit)
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

    // Extended operations (with default implementations)
    fn supports_extended_ops(&self) -> bool;
    async fn delete(&self, url: &str, recursive: bool, opts: &ProtocolOptions) -> AftResult<()>;
    async fn rename(&self, from: &str, to: &str, opts: &ProtocolOptions) -> AftResult<()>;
    async fn mkdir(&self, url: &str, opts: &ProtocolOptions) -> AftResult<()>;
    async fn exists(&self, url: &str, opts: &ProtocolOptions) -> AftResult<bool>;
    async fn list_recursive(&self, url: &str, opts: &ProtocolOptions, max_depth: usize) -> AftResult<Vec<DirectoryEntry>>;
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
- **Hardware-accelerated CRC32** — Per-frame integrity via `crc32fast` using
  SSE4.2 / ARM CRC32 hardware instructions when available
- **Widened XOR** — Hybrid crypto XOR step processes `u64` chunks (~8× fewer
  loop iterations than byte-at-a-time)
- **Connection pooling** — reqwest's built-in pool for HTTP
- **Release profile** — LTO, single codegen unit, stripped, panic=abort (~9 MB)

## FIPS 140-3 Build

For DoD and government environments requiring FIPS 140-3 validated cryptography, build with the `fips` feature flag to switch the TLS provider to [aws-lc-rs](https://github.com/aws/aws-lc-rs) (FIPS 140-3 validated):

```bash
cargo build --release --features fips
```

This replaces the default `ring` crypto backend with `aws-lc-rs` for all TLS operations, restricting cipher suites to FIPS-approved AES-256-GCM and AES-128-GCM with ECDHE key exchange.

> **Note:** The `fips` feature requires a C/C++ toolchain (cmake, clang/gcc) for
> building aws-lc-rs from source.

## Export Control Notice

This software contains cryptographic functionality and is subject to U.S. export control regulations under the Export Administration Regulations (EAR).

- **ECCN:** 5D002 — Information Security software using or performing cryptographic functions
- **License Exception:** ENC (§740.17(b)) — Publicly available open-source encryption software

**Cryptographic components included:**

| Algorithm             | Key Length      | Purpose                                             |
| --------------------- | --------------- | --------------------------------------------------- |
| AES-256-GCM           | 256-bit         | Authenticated encryption (PQC file encryption, TLS) |
| AES-128-GCM           | 128-bit         | TLS cipher suite                                    |
| ML-KEM / Kyber1024    | N/A (KEM)       | Post-quantum key encapsulation (NIST FIPS 203)      |
| HMAC-SHA256           | 256-bit         | Challenge/response authentication                   |
| SHA-256, SHA-512, MD5 | N/A (hash)      | Integrity verification                              |
| TLS 1.2+ (rustls)     | Varies          | Transport encryption                                |
| QUIC (quinn)          | Varies          | Transport encryption                                |
| Neural network cipher | Model-dependent | Experimental MLP autoencoder encryption             |

This software has been publicly released and a notification has been submitted to the U.S. Bureau of Industry and Security (BIS) and the National Security Agency (NSA) in accordance with EAR §742.15(b). This software may be exported and re-exported under License Exception ENC without further authorization, except to embargoed destinations and denied persons per EAR Part 746 and the Entity List (Supplement No. 4 to Part 744).

**This notice does not constitute legal advice.** Consult an export control attorney for your specific use case.

## License

This project is dual-licensed:

- **AGPL-3.0-or-later** — Free for open-source use under the terms of the [GNU Affero General Public License v3.0](LICENSE).
- **Commercial License** — For proprietary/commercial use without AGPL obligations, contact [NERVOSYS](https://nervosys.ai) for a commercial license.
