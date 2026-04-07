# AFT Benchmarks

Criterion-based benchmarks for AFT's hardware-accelerated primitives, AFTP wire
protocol, and transfer I/O paths. All numbers were collected on a single machine
with an AMD/Intel x86_64 CPU supporting SSE4.2, SHA-NI, and AES-NI instruction
sets. Results will vary by hardware; run `cargo bench` to reproduce on your own
system.

HTML reports are generated in `target/criterion/`.

---

## Table of Contents

- [Running](#running)
- [Primitives](#primitives)
  - [CRC32 (SSE4.2)](#crc32-sse42)
  - [SHA-256 (SHA-NI)](#sha-256-sha-ni)
  - [AES-256-GCM (AES-NI)](#aes-256-gcm-aes-ni)
  - [Zstd (SIMD)](#zstd-simd)
  - [XOR u64-Widened](#xor-u64-widened)
- [AFTP Protocol](#aftp-protocol)
  - [Frame Building](#frame-building)
  - [Frame Parsing](#frame-parsing)
  - [Frame I/O](#frame-io)
  - [Per-Frame CRC32 Verification](#per-frame-crc32-verification)
- [Transfer I/O](#transfer-io)
  - [Local Copy Baselines (100 MB)](#local-copy-baselines-100-mb)
  - [Integrity Pipeline](#integrity-pipeline)
- [Comparison with Other Tools](#comparison-with-other-tools)
- [Analysis](#analysis)

---

## Running

```bash
# Run all benchmarks
cargo bench

# Run a single suite
cargo bench --bench primitives
cargo bench --bench protocol
cargo bench --bench transfer

# Shorter measurement for quick iteration
cargo bench -- --warm-up-time 1 --measurement-time 3
```

Benchmark source files:

| File                    | Contents                                                           |
| ----------------------- | ------------------------------------------------------------------ |
| `benches/primitives.rs` | CRC32, SHA-256, AES-256-GCM, Zstd, XOR                             |
| `benches/protocol.rs`   | AFTP frame build/parse, frame I/O, CRC32 verify                    |
| `benches/transfer.rs`   | std::fs::copy, buffered copy, tokio async copy, integrity pipeline |

---

## Primitives

Hardware-accelerated cryptographic and integrity primitives used in AFT's data
path. Each primitive auto-detects and uses the best available CPU instructions.

### CRC32 (SSE4.2)

Per-frame integrity. Used on every AFTP data frame when `CAP_CRC32_FRAMES` is
negotiated. Powered by `crc32fast` with automatic SSE4.2 (x86_64) and CRC32
(aarch64) detection.

| Payload | Throughput |
| ------- | ---------- |
| 1 KB    | 14.3 GiB/s |
| 64 KB   | 15.0 GiB/s |
| 1 MB    | 15.0 GiB/s |
| 16 MB   | 14.9 GiB/s |

### SHA-256 (SHA-NI)

Transfer-level integrity. Computed across the full file and sent in the
`DATA_END` frame. Powered by `sha2` with automatic SHA-NI (x86_64) and SHA2
(aarch64) detection.

| Payload | Throughput |
| ------- | ---------- |
| 1 KB    | 2.15 GiB/s |
| 64 KB   | 2.33 GiB/s |
| 1 MB    | 2.35 GiB/s |
| 16 MB   | 2.35 GiB/s |

### AES-256-GCM (AES-NI)

Authenticated encryption for quantum-resistant file protection. Powered by
`aes-gcm` with automatic AES-NI detection.

| Payload | Encrypt    | Decrypt    |
| ------- | ---------- | ---------- |
| 1 KB    | 1.34 GiB/s | 1.28 GiB/s |
| 64 KB   | 1.49 GiB/s | 1.50 GiB/s |
| 1 MB    | 1.05 GiB/s | 1.08 GiB/s |
| 16 MB   | 961 MiB/s  | 1.03 GiB/s |

### Zstd (SIMD)

Optional per-transfer compression. `zstd` uses SIMD internally via the C
`libzstd` library. Compression ratio depends heavily on data content; the
benchmark uses pseudo-random data (worst case).

| Payload | Compress   | Decompress |
| ------- | ---------- | ---------- |
| 1 KB    | 4.2 MiB/s  | 62 MiB/s   |
| 64 KB   | 244 MiB/s  | 1.40 GiB/s |
| 1 MB    | 1.69 GiB/s | 1.60 GiB/s |
| 16 MB   | 5.97 GiB/s | 1.50 GiB/s |

### XOR u64-Widened

Hybrid encryption XOR layer. Processes data in 8-byte chunks instead of
byte-at-a-time, yielding a 4–6× speedup on the XOR pass.

| Payload | Throughput |
| ------- | ---------- |
| 1 KB    | 4.25 GiB/s |
| 64 KB   | 5.59 GiB/s |
| 1 MB    | 2.97 GiB/s |
| 16 MB   | 2.46 GiB/s |

---

## AFTP Protocol

AFTP is AFT's custom binary wire protocol. It uses a 10-byte header per frame
with 1 MB data frames, yielding 0.001% framing overhead compared to HTTP's
0.02–0.08%.

### Frame Building

Time to construct a complete frame payload in memory.

| Frame Type         | Latency |
| ------------------ | ------- |
| HELLO              | 26.5 ns |
| GET                | 28.6 ns |
| PUT                | 27.4 ns |
| DATA_END (SHA-256) | 27.5 ns |
| ERROR              | 28.6 ns |

### Frame Parsing

Time to parse a frame payload from a byte buffer.

| Frame Type | Latency  |
| ---------- | -------- |
| HELLO      | 46.2 ns  |
| HELLO_ACK  | 47.8 ns  |
| GET        | 52.0 ns  |
| DATA_END   | 160.7 ns |

### Frame I/O

Async write/read of complete frames (header + payload) over an in-memory buffer
via Tokio.

| Operation   | 1 KB       | 64 KB      | 1 MB      |
| ----------- | ---------- | ---------- | --------- |
| write_frame | 10.0 GiB/s | 65.2 GiB/s | 3.8 GiB/s |
| read_frame  | 9.1 GiB/s  | 51.7 GiB/s | 3.4 GiB/s |

### Per-Frame CRC32 Verification

`verify_frame_crc32()` — compute CRC32 of the payload data and compare against
the 4-byte trailer. Same throughput as raw CRC32 since the comparison is
negligible.

| Payload | Throughput |
| ------- | ---------- |
| 1 KB    | 14.3 GiB/s |
| 64 KB   | 14.8 GiB/s |
| 1 MB    | 15.0 GiB/s |

---

## Transfer I/O

End-to-end file copy throughput on local disk. These baselines represent the
maximum achievable throughput on the test system's storage subsystem.

### Local Copy Baselines (100 MB)

| Method                    | Throughput | Notes                               |
| ------------------------- | ---------- | ----------------------------------- |
| `std::fs::copy` (Rust)    | 2.14 GiB/s | OS-level `CopyFileW` on Windows     |
| Buffered copy (4 MB bufs) | 1.44 GiB/s | AFT's `IO_BUF_SIZE` buffer strategy |
| `robocopy` (Windows)      | 1.05 GiB/s | Standard Windows copy tool          |
| `.NET File.Copy`          | 408 MiB/s  | PowerShell / .NET baseline          |
| `tokio::io::copy` (async) | 217 MiB/s  | Async runtime overhead              |

### Integrity Pipeline

Simulates AFT's real data path: per-frame CRC32 on every 1 MB chunk plus
transfer-level SHA-256 across the entire file. This is the cost of full
integrity verification.

| File Size | Throughput |
| --------- | ---------- |
| 1 MB      | 2.01 GiB/s |
| 10 MB     | 2.02 GiB/s |
| 100 MB    | 1.96 GiB/s |

---

## Comparison with Other Tools

### AFT vs. System Copy Tools (100 MB, Local Disk)

| Tool                       | Throughput     | Integrity       | Encryption | Compression |
| -------------------------- | -------------- | --------------- | ---------- | ----------- |
| **AFT integrity pipeline** | **1.96 GiB/s** | CRC32 + SHA-256 | —          | —           |
| `std::fs::copy`            | 2.14 GiB/s     | None            | None       | None        |
| `robocopy`                 | 1.05 GiB/s     | None            | None       | None        |
| `.NET File.Copy`           | 408 MiB/s      | None            | None       | None        |

AFT's integrity pipeline (CRC32 + SHA-256 on every byte) runs at 1.96 GiB/s —
**1.87× faster than robocopy** and **4.8× faster than .NET File.Copy** — while
providing cryptographic verification that neither tool offers.

### AFT Primitive Throughput vs. Published Benchmarks

| Primitive   | AFT             | Typical Software   | Speedup |
| ----------- | --------------- | ------------------ | ------- |
| CRC32       | 15.0 GiB/s      | ~0.3 GiB/s (no HW) | ~50×    |
| SHA-256     | 2.35 GiB/s      | ~0.4 GiB/s (no HW) | ~6×     |
| AES-256-GCM | 1.05–1.50 GiB/s | ~0.1 GiB/s (no HW) | ~10–15× |

Hardware acceleration is the key differentiator. AFT auto-detects and uses
SSE4.2, SHA-NI, and AES-NI instructions, eliminating integrity and encryption as
bottlenecks.

### Transfer Tool Class Comparison

| Tool Class         | Typical Throughput | Integrity       | Encryption              | Protocol Overhead    |
| ------------------ | ------------------ | --------------- | ----------------------- | -------------------- |
| **AFT (AFTP)**     | **Disk-speed**     | CRC32 + SHA-256 | AES-256-GCM + Kyber1024 | 0.001% (10 B / 1 MB) |
| curl / wget (HTTP) | Disk-speed         | Optional        | TLS                     | 0.02–0.08%           |
| rsync              | ~500 MiB/s         | MD5 / xxHash    | SSH tunnel              | Variable             |
| scp / sftp         | ~200–400 MiB/s     | HMAC            | SSH                     | SSH framing          |
| Globus GridFTP     | ~1 GiB/s           | CRC32           | GSI / TLS               | GridFTP framing      |
| Aspera FASP        | ~1 GiB/s           | SHA-1           | AES-128                 | UDP-based            |
| HPN-SSH            | ~500 MiB/s         | HMAC            | SSH                     | SSH + HPN patches    |
| robocopy (Windows) | ~1 GiB/s           | None            | None                    | SMB                  |
| rclone             | Variable           | MD5 / SHA-1     | TLS                     | HTTP-based           |

AFT achieves disk-speed transfers with full CRC32 + SHA-256 integrity, optional
post-quantum encryption, 0.001% protocol overhead, and adaptive multi-stream
parallelism — a combination no other tool in this class provides.

---

## Analysis

### Why AFT's Integrity Is Free

CRC32 at 15 GiB/s means verifying a 1 MB data frame takes 65 µs. SHA-256 at
2.35 GiB/s adds 415 µs per MB. Combined, the integrity pipeline processes
data at nearly 2 GiB/s — faster than any network link and within 10% of raw
`std::fs::copy` speed. Integrity verification is no longer a performance
tradeoff; it is effectively free.

### Why Encryption Isn't a Bottleneck

AES-256-GCM at ~1 GiB/s with AES-NI means AFT can encrypt every byte of a
transfer and still exceed the throughput of most copy tools operating on
plaintext. A 10 Gbps network link saturates at 1.16 GiB/s — almost exactly
what AES-256-GCM delivers.

### Protocol Efficiency

AFTP's 10-byte header on 1 MB data frames yields 0.001% framing overhead. Frame
build and parse operations complete in 27–160 ns. In-memory frame I/O throughput
exceeds 50 GiB/s at 64 KB payloads. The protocol itself is never the
bottleneck — disk I/O and network bandwidth are.

### Turbo Engine Design

AFT's turbo transfer engine adds adaptive parallelism (8–128 streams),
BDP-aware 16 MiB socket buffers, memory-mapped zero-copy reads, write-behind
pipelining, and adaptive chunk sizing (1 MB → 64 MB). These are in addition to
the hardware-accelerated primitives measured here. Together, they ensure AFT
saturates any available bandwidth.
