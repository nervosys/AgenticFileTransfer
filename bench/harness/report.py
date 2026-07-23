#!/usr/bin/env python3
"""report.py -- fold results.jsonl into results.json + a printed summary table.

Median is over the successful runs only. A cell with no successful run is
reported as its failure status, never silently dropped.
"""
import json, statistics, sys, collections, os

RAW = sys.argv[1] if len(sys.argv) > 1 else "/root/bench/results.jsonl"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/root/bench/results.json"

REGIMES = ["perfect", "good", "bad", "broken"]
WORKLOADS = ["small_500k", "single_50m", "single_500m", "tree_2000x1k", "tree_400x1m"]
TOOLS = ["rsync", "atp-tcp", "atp-rq", "aft", "aft-turbo"]

REGIME_SPEC = {
    "perfect": "1gbit, 2ms delay, 0% loss",
    "good": "200mbit, 25ms delay, 0.1% loss",
    "bad": "50mbit, 80ms +/-20ms delay, 2% loss",
    "broken": "10mbit, 200ms +/-50ms delay, 10% loss, 5% reorder, 1% duplicate",
}

runs = [json.loads(l) for l in open(RAW) if l.strip()]

cells = collections.defaultdict(list)
for r in runs:
    cells[(r["regime"], r["workload"], r["tool"])].append(r)

summary = {}
for key, rs in cells.items():
    ok = [r for r in rs if r["status"] == "ok"]
    entry = {"runs": len(rs), "ok_runs": len(ok)}
    if ok:
        entry["median_seconds"] = round(statistics.median(r["seconds"] for r in ok), 3)
        entry["all_seconds"] = sorted(round(r["seconds"], 3) for r in ok)
        entry["peak_rss_kb"] = max(r["rss_kb"] for r in ok if r["rss_kb"])
        entry["bytes"] = ok[0]["bytes"]
        entry["status"] = "ok"
    else:
        entry["status"] = rs[0]["status"]
        entry["note"] = rs[0]["note"]
    summary["|".join(key)] = entry

doc = {
    "regimes": REGIME_SPEC,
    "tools": TOOLS,
    "runs_per_cell": max((len(v) for v in cells.values()), default=0),
    "statistic": "median of successful runs",
    "summary": summary,
    "raw": runs,
}
json.dump(doc, open(OUT, "w"), indent=2)


def cell(regime, wl, tool):
    e = summary.get("|".join((regime, wl, tool)))
    if e is None:
        return "-"
    if e["status"] != "ok":
        return {"error": "ERR", "timeout": "TIMEOUT", "mismatch": "BADDATA"}.get(e["status"], "ERR")
    return f"{e['median_seconds']:.2f}"


def secs(regime, wl, tool):
    e = summary.get("|".join((regime, wl, tool)))
    return e["median_seconds"] if e and e["status"] == "ok" else None


for regime in REGIMES:
    present = [w for w in WORKLOADS if any(("|".join((regime, w, t))) in summary for t in TOOLS)]
    if not present:
        continue
    print(f"\n=== {regime.upper()}  ({REGIME_SPEC[regime]}) ===")
    hdr = f"{'workload':<14}" + "".join(f"{t:>11}" for t in TOOLS) + f"{'aft/atp-tcp':>13}{'aftT/atp-tcp':>14}"
    print(hdr)
    print("-" * len(hdr))
    for wl in present:
        row = f"{wl:<14}" + "".join(f"{cell(regime, wl, t):>11}" for t in TOOLS)
        a, at, t_ = secs(regime, wl, "aft"), secs(regime, wl, "atp-tcp"), secs(regime, wl, "aft-turbo")
        row += f"{(f'{a/at:.2f}x' if a and at else 'n/a'):>13}"
        row += f"{(f'{t_/at:.2f}x' if t_ and at else 'n/a'):>14}"
        print(row)

print("\n=== PEAK RSS (MB, client process, max over runs) ===")
hdr = f"{'regime/workload':<26}" + "".join(f"{t:>11}" for t in TOOLS)
print(hdr); print("-" * len(hdr))
for regime in REGIMES:
    for wl in WORKLOADS:
        if not any(("|".join((regime, wl, t))) in summary for t in TOOLS):
            continue
        vals = []
        for t in TOOLS:
            e = summary.get("|".join((regime, wl, t)))
            vals.append(f"{e['peak_rss_kb']/1024:.1f}" if e and e["status"] == "ok" else "-")
        print(f"{regime + '/' + wl:<26}" + "".join(f"{v:>11}" for v in vals))

print("\n=== FAILURES ===")
seen = set()
for k, e in sorted(summary.items()):
    if e["status"] != "ok":
        note = e.get("note", "")
        print(f"  {k:<45} {e['status']:<9} {note[:150]}")
        seen.add(e["status"])
if not seen:
    print("  none")
print(f"\nresults.json -> {os.path.abspath(OUT)}")
