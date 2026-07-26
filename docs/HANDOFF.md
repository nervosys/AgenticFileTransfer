# AFTP v2 / FEC Data Plane — Engineering Handoff

Status as of the merge of PR #1 (`AFTP v2: fountain-coded UDP data plane`) to
`master`. This document is the entry point for anyone continuing the work: what
shipped, how it fits together, how to reproduce the numbers, the security
posture, and the tracked follow-ups.

---

## 1. What shipped

Six commits on `master` (PR #1, merged):

| Commit    | What                                                                        |
| --------- | --------------------------------------------------------------------------- |
| `b6885cb` | Fountain-coded UDP data plane (`--fec`): RaptorQ codec, envelope, UDP, pacer, scheduler, control-plane frames |
| `eb4197d` | Request BBR congestion control on TCP sockets (survive lossy links)          |
| `4f90660` | README measured head-to-head table                                          |
| `933a8e5` | Default TCP to BBR (fastest on clean links too); `AFT_TCP_CC` override        |
| `61fe8a2` | **Security**: encrypt the FEC data plane (AES-256-GCM), random session id, bound receiver memory |
| `178b52d` | **Security**: gate unauthenticated FEC (M5), patch remotely-exploitable deps, refresh audit docs |

**Headline outcome:** AFT is now the fastest tool measured, or the only one that
completes, in every netem regime — `good` via BBR-TCP, `bad` via BBR-TCP or
`--fec`, `broken` via `--fec` alone. See §4.

---

## 2. Architecture: the FEC data plane

Split-plane AFTP v2. The existing **TCP/TLS control plane** stays as-is and now
also negotiates FEC and carries per-block feedback; a new **UDP data plane**
carries file data as RaptorQ symbols. Loss becomes repair bandwidth instead of a
retransmit round trip.

### Module map (`src/aftp/fec/`)

| File          | Responsibility                                                                 |
| ------------- | ------------------------------------------------------------------------------ |
| `mod.rs`      | `derive_symbol_key`, `random_session_id`, `FEC_MIN_TRANSFER` (1 MiB), re-exports |
| `codec.rs`    | RaptorQ block encode/decode (systematic symbols first), OTI derivation           |
| `envelope.rs` | Per-datagram wire envelope + crypto (see §3)                                    |
| `udp.rs`      | `DataPlane` — UDP socket, 8 MiB buffers, connected-peer filtering, DoS-quiet reject |
| `pacing.rs`   | BBR-style `Pacer` (BtlBw/RTprop filters, gain cycle, token bucket + debt)        |
| `transfer.rs` | Block scheduler (`send_blocks`), receiver (`recv_object_into`), feedback loop, `FileBlockWriter`/`FileBlocks` streaming I/O |

### Control-plane additions

- Frames (`src/aftp/frame.rs`): `FEC_OFFER`, `FEC_ACCEPT`, `FEC_NEEDMORE`,
  `FEC_BLOCK_OK`; capability bit `CAP_FEC`.
- Negotiation is fail-safe: a peer without `CAP_FEC` (or a server that refuses
  it — see §3 M5) transparently uses the reliable TCP path. v1↔v2 interoperate.
- Client entry points: `client.rs::upload_fec`, `download_fec`. Server:
  `server.rs::recv_put_fec`, `serve_get_fec`.

### Key design decisions (don't regress these)

- **Per-block adaptive coding.** Source symbols go first (systematic → memcpy
  decode on a clean link); repair is sprayed on measured loss, decided per
  block. `loss_hint` adapts from NeedMore feedback and decays on clean BlockOk.
- **Bounded sender memory.** `FileBlocks` streams blocks on demand; the encoder
  for a block is dropped on `BlockOk`. Peak RSS ≈ window × block_size + RaptorQ
  working set, independent of file size (window=4, block=8 MiB).
- **Bounded receiver memory** (M4 fix). Downloads stream to a `.aftp-part` temp
  via `FileBlockWriter`, SHA-256-verify, then atomic rename (fail-closed at the
  destination). `recv_object_into` caps concurrent decoders to `params.window`.
- **Cancellation safety.** `read_frame` is *not* cancellation-safe; the receive
  loops use a reader-task + mpsc channel and a feedback pump, never a bare
  `select!` over `read_frame`. There is a documented finalization-race fix in
  `recv_put_fec` (await the pump, don't abort it) — see the comment there.

---

## 3. Security posture

A pre-release audit initially rated `--fec` **NO-GO** (it shipped plaintext).
All code-level findings are fixed; see `docs/SECURITY.md §4a` for the full
writeup and `memory`/commit messages for rationale.

### Crypto model (authenticated connection = `--auth-token` / `aftps://`)

- **AES-256-GCM per symbol.** Envelope wire **version 2**:
  `prefix(18) || nonce(12) || ciphertext || tag(16)`. The 18-byte header prefix
  is the GCM **AAD** (session/block/len authenticated in the clear); 96-bit
  random nonce per datagram (`OsRng`).
- **Key** = 32-byte `HMAC-SHA256(token, "aft-fec-symbol-key-v2" ‖ session_id)`
  (`derive_symbol_key`). The old HMAC-over-plaintext (v1) scheme is gone.
- **Session id** must be **random** (`random_session_id()` → `OsRng.next_u64()`),
  never derived from public params — a predictable id makes the key predictable
  and enables replay. Set in both `upload_fec` and `serve_get_fec`; exchanged in
  the offer on the control plane.
- **Unauthenticated FEC = CRC32 only, refused by default (M5).** An
  unauthenticated server does not advertise `CAP_FEC`; clients fall back to the
  reliable path. Opt in only with the server flag `--fec-insecure`
  (`AftpServer::with_unauthenticated_fec`) for physically trusted links. Never
  for CUI.

Tests that lock these in (all in `tests/integration_tests.rs`, and
`envelope.rs`): `payload_is_encrypted_on_the_wire`, `each_encode_uses_a_fresh_nonce`,
`nonce_tampering_is_rejected`, `auth_downgrade_is_refused`,
`tampering_is_rejected_everywhere`, `unauthenticated_fec_is_refused_by_default`,
`fec_{up,down}load_with_authenticated_symbols`.

### Dependency advisories

First pass (semver-compatible): `quinn-proto` → 0.11.15 (remote memory
exhaustion), `rustls-webpki` → 0.103.13 (cert-validation + CRL panic),
`crossbeam-epoch` → 0.9.20.

Second pass (#1, major bumps — see §6): `russh` 0.46 → 0.62
(RUSTSEC-2026-0154/0153), `rust-s3` 0.35 → 0.37.2 (clears the `quick-xml` 0.32
and `rustls-webpki` 0.101.7 pins: RUSTSEC-2026-0194/0195/0098/0099/0104),
`pqc_kyber` → `ml-kem` 0.3.2 (KyberSlash). Remaining known item: `rsa` Marvin
(RUSTSEC-2023-0071), now transitive-only via `russh`/`ssh-key`, no upstream fix
— monitor. Full triage in `docs/SECURITY.md` Appendix A.

### Known, documented limitations

- **H3 — FIPS (FEC now covered).** The FEC data plane's AEAD and KDF route
  through `src/aftp/fec/symcrypto.rs`, which uses `aws-lc-rs` (FIPS 140-3
  validated) under `--features fips` and RustCrypto `aes-gcm`/`hmac` otherwise —
  so a `--features fips` build now keeps `--fec` bulk data inside the validated
  module, matching the TLS control plane. Wire format is identical across
  backends (a KDF known-answer test locks this in), so FIPS and default builds
  interoperate. **Still outside the boundary:** the PQC pipeline (`pqc_kyber`)
  and the neural components — those remain RustCrypto/unvalidated regardless of
  the feature. A default (non-FIPS) build still uses RustCrypto for FEC.

---

## 4. Performance & benchmarks

TCP congestion control: `tune_tcp_socket` (`src/aftp/transport.rs`) requests
**BBR** by default on Linux (`setsockopt(TCP_CONGESTION)`), overridable with
`AFT_TCP_CC` (e.g. `AFT_TCP_CC=cubic`). BBR is best all-round: tight tails on
clean links, and it does not collapse on random loss.

Measured, 50 MB file, `tc` netem (both directions), medians:

| Regime (rate / delay / loss)         | aft (TCP) | aft `--fec` | atp-tcp | atp-rq | rsync |
| ------------------------------------ | --------- | ----------- | ------- | ------ | ----- |
| good (200 Mbit / 25 ms / 0.1%)       | **2.8 s** (9-run) | 3.4 s | 3.0 s | 3.0 s | 3.3 s |
| bad (50 Mbit / 80 ms / 2%)           | 14.8 s    | **13.0 s**  | timeout | timeout | timeout |
| broken (10 Mbit / 200 ms / 10%+reorder) | timeout | **103 s** (3/3) | timeout | timeout | timeout |

`aft --fec` peak RSS 136–168 MB (bounded, file-size independent) vs ~8–13 MB for
the others — the memory cost is real and documented, not a win.

**Reproduce:** harness in `bench/` (`bench/README.md`). Linux/root only
(developed on WSL2 Debian). Raw data: `bench/results_good_9run.jsonl` (the
9-run `good` row), `bench/results_fec_final.jsonl`, `bench/results_tcp_bbr.jsonl`,
`bench/results_fec.jsonl`, `bench/results.jsonl`. High run-to-run variance on
`good` — use ≥9 runs for a stable median (a 3-run sample wrongly showed AFT
behind atp; 9 runs corrected it).

---

## 5. Build, test, verify

```bash
cargo build --release                       # LTO, ~2-3 min
cargo test --lib                            # 76 lib tests
cargo test --release --test integration_tests   # 307 tests (FEC e2e are release-only)
```

**CI gotcha:** `.github/workflows/ci.yml` runs `cargo clippy --all-targets --
-D warnings` on **Linux**. Windows and Linux compile different `cfg` blocks, so
**always verify clippy on Linux** (e.g. WSL) before pushing — a Windows-clean
clippy can still fail CI, and vice versa. FEC e2e tests are `#[ignore]` in debug
(too slow unoptimized); run them with `--release`.

The FEC transfer paths need real sockets; the e2e tests bind localhost UDP.

---

## 6. Tracked follow-ups

### Done (this cycle)

- **#5 — QUIC-datagram data plane** (`quic_dgram.rs`) and **whole-tree packing**
  (Merkle manifest, `manifest.rs`). QUIC-dgram is negotiated end-to-end via
  `CAP_FEC_QUIC` (0x80) across all transfer paths; tree packing folds a directory
  into one fountain-coded object. Gated behind the same auth/consent rules as UDP FEC.
- **#4 — Client-side consent gate for unauthenticated FEC.** The client now
  refuses to advertise `CAP_FEC` on an unauthenticated connection unless it opts
  in with `--fec-insecure` (`with_unauthenticated_fec(true)`). Both ends must
  consent; the gate lives *before* capability advertisement in `client.rs::connect`
  so the server is never offered a plane the client will silently drop. Locked in
  by `unauthenticated_client_refuses_fec_without_optin`.
- **#3 — Broken-regime performance.** **Root cause: the receiver's patience timer
  was seeded from a hardcoded 50 ms RTT** (→ 100 ms patience), which on the
  broken regime's ~400 ms RTT fired NeedMore long before symbols could plausibly
  arrive, provoking premature repair asks and, often, timeouts. Fix: seed the
  patience timer from a **measured control-plane RTT** — client GET→HEAD_RESP,
  server HELLO_ACK→first-command — clamped to [50 ms, 500 ms]
  (`client.rs::download_fec`, `server.rs::recv_fec_object`).

  A/B on the broken regime (10 Mbit / 200 ms±50 / 10% loss / 5% reorder, 50 MB
  upload, `--fec-insecure`, `n=5`):

  | Seed | runs (s) | timeouts |
  | ---- | -------- | -------- |
  | fixed 50 ms (baseline) | 139.7, **T/O**, **T/O**, 136.7, 167.5 | 2/5 |
  | measured RTT (fix)     | 68.8, 85.5, 79.0, 69.1, 152.8 | 0/5 |

  Timeouts eliminated; median ~79 s (was ~137 s best-finish); best case 68.8 s.

  **Instrumentation kept:** `AFT_FEC_TRACE=1` emits per-block `[fec]` sender trace
  (spray sizing, `loss_hint`, BtlBw/RTprop, needmore/repair, overhead summary);
  `#[ignore]`d diagnostic test `overhead_under_sustained_loss`. Both gated/off by
  default (OnceLock), zero-cost when unset.

  **Residual (open) findings** — variance is reduced but not gone; the outlier
  (152.8 s) traces to two effects, left as future work:
  1. **Startup blindness.** The first blocks spray with `loss_hint=0` → zero
     proactive repair; a heavily-hit early block (observed 100% loss on block 1)
     eats a full-block repair round + a patience wait. A small nonzero initial
     `loss_hint` (or carrying it across the tree) would blunt this.
  2. **RTprop filter pollution.** Patience-delayed feedback timing leaks into the
     pacer's RTprop windowed-min (observed climbing to ~25 s). Harmless to BtlBw
     today, but the NeedMore path should not feed RTT samples at all.

- **#2 — FIPS-route the FEC crypto.** The data plane's AEAD + KDF are
  centralized in `src/aftp/fec/symcrypto.rs` (`seal`/`open`/`hmac_sha256`), with
  a RustCrypto backend by default and an `aws-lc-rs` (FIPS 140-3) backend under
  `--features fips`. `derive_symbol_key` and `envelope.rs` call it; nothing else
  in the FEC plane touches an AEAD/MAC directly. Wire format is identical across
  backends — a KDF known-answer test + the AEAD round-trips pass under **both**
  feature sets, and `cargo clippy --all-targets [-]-features fips -D warnings`
  is clean on Linux. Still RustCrypto/unvalidated regardless of the feature: the
  PQC (`pqc_kyber`) and neural pipelines.

- **#1 — Dependency major-bump migration.**
  - **`russh` 0.46 → 0.62** (RUSTSEC-2026-0154/0153). `russh-keys` folded into
    `russh::keys`; `check_server_key` now takes `ssh_key::PublicKey` and the
    `client::Handler` is a native async-fn-in-trait (dropped `#[async_trait]` on
    that impl); `authenticate_publickey` takes a `PrivateKeyWithHashAlg` and auth
    methods return `AuthResult` (`.success()`). Reworked in `src/protocols/sftp.rs`.
  - **`rust-s3` 0.35.1 → 0.37.2** — API-compatible (S3 handler unchanged); pulls
    `quick-xml` 0.38 (RUSTSEC-2026-0194/0195) and `rustls-webpki` 0.103
    (RUSTSEC-2026-0098/0099/0104), so the old 0.32/0.101.7 pins are gone.
  - **`pqc_kyber` 0.7 → `ml-kem` 0.3.2** (KyberSlash, no upstream fix). Deliberate
    **breaking** algorithm change: round-3 Kyber1024 → FIPS-203 ML-KEM-1024.
    `src/crypto/pqc.rs` bumps the key-file version 1→2 / algorithm 0→1 and rejects
    legacy files with a "regenerate with `aft keygen`" error. Round-trip +
    legacy-rejection tests added. User-facing "Kyber1024" strings updated to
    "ML-KEM-1024"; `"kyber"` kept as a CLI alias.
  - **`rsa` (Marvin, RUSTSEC-2023-0071)** — now **transitive-only** via
    `russh`/`ssh-key` (0.10.0-rc.18); no fixed release exists upstream. Monitor
    item; would require dropping RSA SSH host-key support to remove entirely.

  Verified on Linux: `cargo build --lib`, `cargo test --lib` (104 pass), and
  `cargo clippy --all-targets -- -D warnings` all green.

### Remaining

*(none of the originally tracked follow-ups remain open; the `rsa` transitive
advisory above is a monitor item, not an actionable bump.)*

---

## 7. Gotchas / environment notes

- **WSL benchmark env** lives at `/root/bench` (`wsl -d Debian -u root`); prefix
  `MSYS_NO_PATHCONV=1` when passing `/mnt/c` paths from Git Bash. Rebuild the
  Linux binary with `C:\Users\adamm\wslbuild.sh` (rsync + `cargo build
  --release`). `\\wsl$\...` is access-denied for root files — use `wsl ... cat`.
- **Nested WSL-in-Git-Bash quoting** is fragile: `for`-loop variables and
  `$VAR` inside `wsl bash -c '...'` sometimes don't survive. Prefer explicit,
  chained invocations over loops; write scripts as files if they're non-trivial
  (watch for CRLF — Windows-written `.sh` files break `bash` with `set -e`).
- **BBR module**: the `good`/`bad` TCP numbers require `modprobe tcp_bbr` on the
  host; otherwise AFT silently falls back to the kernel default. Verify with
  `sysctl net.ipv4.tcp_available_congestion_control`.

---

## 8. Cross-references

- `docs/SECURITY.md` — full CVE/MITRE/NIST-FIPS/CMMC assessment; §4a is the FEC
  data plane; Appendix A is the current dependency advisory triage.
- `docs/BENCHMARKS.md` — methodology, per-run figures, honest caveats.
- `bench/README.md` — harness usage and regime definitions.
