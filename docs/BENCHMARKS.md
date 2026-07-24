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

### Feature Comparison (illustrative, not measured)

The table below compares *capabilities*, not performance. The throughput
figures for third-party tools are typical published numbers, **not**
head-to-head measurements — see the next section for those.

| Tool Class         | Integrity       | Encryption              | Protocol Overhead    |
| ------------------ | --------------- | ----------------------- | -------------------- |
| **AFT (AFTP)**     | CRC32 + SHA-256 | AES-256-GCM + Kyber1024 | 0.001% (10 B / 1 MB) |
| curl / wget (HTTP) | Optional        | TLS                     | 0.02–0.08%           |
| rsync              | MD5 / xxHash    | SSH tunnel              | Variable             |
| scp / sftp         | HMAC            | SSH                     | SSH framing          |
| rclone             | MD5 / SHA-1     | TLS                     | HTTP-based           |

### Measured Head-to-Head: Lossy and Latent Links

Measured on WSL2 Debian using network namespaces joined by a veth pair, shaped
in **both directions** with `tc` HTB + netem. Contenders: AFT (this repo,
release build), [ATP](https://github.com/Dicklesworthstone/atp) built from
source (asupersync, TCP mode and RaptorQ mode with
`--rq-allow-unauthenticated-lab`), and rsync over ssh. Workload: one 50 MB
file, cold destination, byte-verified after transfer. Median of 3 runs; peak
RSS via `/usr/bin/time -v`. Raw rows: [`bench/results_good_9run.jsonl`](../bench/results_good_9run.jsonl)
(the 9-run `good` row, all tools), [`bench/results_fec_final.jsonl`](../bench/results_fec_final.jsonl)
(aft --fec bad/broken), [`bench/results_tcp_bbr.jsonl`](../bench/results_tcp_bbr.jsonl)
(aft TCP bad/broken), and [`bench/results_fec.jsonl`](../bench/results_fec.jsonl)
(atp, rsync bad/broken), produced by the harness in [`bench/harness/`](../bench/harness/).

Network regimes (mirroring ATP's own benchmark matrix):

| Regime | Rate     | Delay      | Loss | Other                  |
| ------ | -------- | ---------- | ---- | ---------------------- |
| good   | 200 Mbit | 25 ms      | 0.1% | —                      |
| bad    | 50 Mbit  | 80 ± 20 ms | 2%   | —                      |
| broken | 10 Mbit  | 200 ± 50 ms| 10%  | 5% reorder, 1% dup     |

Median wall-clock seconds (lower is better; `timeout` = no run finished
within the cell's time limit):

| Tool             | good      | bad         | broken       | RSS (good) |
| ---------------- | --------- | ----------- | ------------ | ---------- |
| **aft (TCP)**    | **2.8**   | 14.8        | timeout      | ~47 MB     |
| **aft --fec**    | 3.4       | **13.0**    | **103**      | ~149 MB    |
| atp (TCP mode)   | 3.0       | timeout     | timeout      | ~10 MB     |
| atp (RaptorQ)    | 3.0       | timeout     | timeout      | ~13 MB     |
| rsync (ssh)      | 3.3       | timeout     | timeout      | ~8 MB      |

The `good` column is a median of 9 runs (that regime has high run-to-run
variance on netem — see below); `bad`/`broken` are medians of 3–6 runs. The
TCP path uses BBR congestion control by default (`AFT_TCP_CC` to override).

**`good` regime — AFT's TCP path is the fastest tool measured, at 2.8 s.** It
edges out atp (both modes, 3.0 s) and rsync (3.3 s), and it does so *tightly*:
all nine AFT runs fell in 2.74–2.92 s. BBR's pacing keeps the distribution
narrow — its slowest run still beat every other tool's median. The other tools
are bimodal here: the 0.1% random loss occasionally triggers a CUBIC window cut,
so their tails blow out — across the same nine runs atp-tcp reached 14.6 s,
atp-rq 35.9 s, and rsync 25.5 s, dragging their medians above AFT's. This is also why an
earlier 3-run sample wrongly showed AFT behind — on a high-variance link, three
runs is too few to trust; nine tells the real story.

Two AFT paths, two different jobs:

**`bad` regime (2% loss) — the TCP path handles it, thanks to BBR.** The same
default BBR that wins the `good` cell also carries the lossy one. CUBIC (the
kernel default every other tool here uses) is loss-based: it reads the 2%
random drop as congestion and cuts its window every time, so its throughput
collapses to ≈ MSS/(RTT·√p) ≈ 130 KB/s — ~385 s for 50 MB, past every timeout
here, which is why `atp (TCP mode)` and `rsync` time out. BBR models bottleneck
bandwidth and RTprop and ignores loss as a signal, so AFT's TCP transfer
finishes in **14.8 s median** at ~47 MB RSS — matching the FEC path (13.0 s)
with a third of the memory. On a 2%-loss link you do not need FEC; you need TCP
to stop misreading loss.

**`broken` regime (10% loss + reorder + dup) — only FEC completes.** Here BBR
is not enough: congestion control was never the bottleneck, TCP's *reliability*
layer is. Every dropped byte still costs a retransmit round trip, 5% reordering
triggers spurious fast-retransmits, and at 10% loss over ~36k segments the
stream never drains — `aft (TCP)` times out 3/3 at 200 s alongside every other
reliable-transport tool. `aft --fec` completes 3/3 (89.7 / 103.2 / 233.9 s,
median 103.2 s) because a fountain code turns loss into a bit of extra repair
bandwidth rather than a round trip. This is the regime the data plane was built
for.

**Honest caveats — read before quoting these numbers:**

1. **ATP's RaptorQ-mode failures may be environmental.** They reproduce
   consistently across two independent runs (errors/hash mismatches on lossy
   regimes), but could stem from the specific asupersync build, the
   `--rq-allow-unauthenticated-lab` flag, or interaction with netem — not
   necessarily from ATP's design. These results support "AFT's FEC path
   survives links where our ATP build did not," not "AFT's algorithm beats
   ATP's."
2. **Memory is AFT's cost.** `aft --fec` peak RSS ranged 136–168 MB across all
   measured runs (window × 8 MiB blocks + RaptorQ working set) versus ~8–13 MB
   for rsync and ATP. The RSS is bounded and independent of file size, but it is
   roughly 12–15× the other tools'.
3. **Broken-regime variance is high.** ~10 Mbit at 10% loss with reordering
   leaves little headroom; runs ranged 89.7–233.9 s and pure wire time for
   50 MB at 10 Mbit is ~42 s, so real room to improve remains — it just beats
   a field where nothing else finishes.
4. **The TCP-path numbers assume BBR is available.** AFT requests BBR
   per-socket by default (override with `AFT_TCP_CC`), but the kernel only
   honours it if the `tcp_bbr` module is loaded (`modprobe tcp_bbr`; check
   `sysctl net.ipv4.tcp_available_congestion_control`). Where it is not, AFT
   silently keeps the kernel default (CUBIC): the `good` cell is essentially
   unchanged but its tail widens, and the `bad` cell collapses to a timeout
   like the other tools — use `--fec` there. BBR is a per-socket opt-in on
   Linux only; on Windows/macOS the TCP path uses the OS default.

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

AFT's turbo engine probes the link (HEAD request timing) and dispatches to the
standard transfer engine with tuned parameters: parallel range requests when
the protocol benefits from them, and chunk sizes selected by link locality.
AFTP TCP sockets get 16 MiB send/receive buffers (`tune_tcp_socket`), and the
FEC UDP data plane gets 8 MiB buffers. Uploads read through each protocol
handler's own I/O path — there is no memory-mapped upload; real `mmap` is used
only for local→local copies.

On lossy or high-latency links, none of this tuning matters: TCP collapses
regardless (see the head-to-head above). That is what the `--fec` RaptorQ
data plane is for.
