# Head-to-Head Benchmark Harness

Linux-only (developed on WSL2 Debian, needs root). Builds two network
namespaces joined by a veth pair, impairs the link with `tc` HTB + netem in
both directions, and runs each contender pushing the same workloads from
client namespace to server namespace, recording wall clock and peak RSS
(`/usr/bin/time -v`) as JSON Lines.

| File           | Purpose                                                       |
| -------------- | ------------------------------------------------------------- |
| `netem.sh`     | Create/destroy the namespace pair; apply a named regime       |
| `workloads.sh` | Generate workloads (500 KB, 50 MB, 500 MB, file trees)        |
| `run.sh`       | Orchestrate: regimes × tools × workloads × runs → JSONL       |
| `probe.sh`     | Sanity-check the shaped link (ping RTT, iperf-style rate)     |
| `report.py`    | Summarize a results file into per-cell medians                |
| `purge.py`     | Drop selected rows from a results file                        |

Contender tools expected on PATH inside the namespaces: `rsync`, `atp`
(built from [Dicklesworthstone/atp](https://github.com/Dicklesworthstone/atp)),
and the `aft` release binary (`run.sh` looks for it in `/root/bench/aft-src/target/release`).

```bash
# All defaults: 4 regimes, all tools, per-regime workloads, 3 runs each
sudo bash run.sh

# Focused run, e.g. only the FEC path on the lossy regimes
sudo env TOOLS=aft-fec REGIMES="bad broken" WORKLOADS=single_50m RUNS=3 \
    OUT=results_focus.jsonl bash run.sh

# RESUME=1 appends to OUT and skips cells that already have >= RUNS rows
```

Network regimes (applied both directions):

| Regime  | Rate     | Delay       | Loss | Other              |
| ------- | -------- | ----------- | ---- | ------------------ |
| perfect | 1 Gbit   | 2 ms        | 0%   | —                  |
| good    | 200 Mbit | 25 ms       | 0.1% | —                  |
| bad     | 50 Mbit  | 80 ± 20 ms  | 2%   | —                  |
| broken  | 10 Mbit  | 200 ± 50 ms | 10%  | 5% reorder, 1% dup |

Result rows: `{tool, workload, regime, run, status, seconds, rss_kb, bytes, note}`.
Transfers are byte-verified after each run; a timeout or hash mismatch is
recorded as a failure row, never silently dropped.

- `results.jsonl` — baseline sweep (rsync, atp-tcp, atp-rq, aft, aft-turbo across
  all four regimes and workloads).
- `results_fec.jsonl` — 50 MB single-file head-to-head including `aft --fec`.
- `results_fec_final.jsonl` — `aft --fec` re-measured with the final binary
  (adaptive receiver patience + sample-driven BBR pacing with a startup guard,
  per-interval delivery deltas, and loss-hint decay); these are the aft rows
  quoted in the docs. good 3.2 s (6/6), bad 13.0 s (6/6), broken 103 s (3/3).

These are the raw data behind the measured tables in
[docs/BENCHMARKS.md](../docs/BENCHMARKS.md).
