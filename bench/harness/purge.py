#!/usr/bin/env python3
"""Drop interrupted (partial) cells and the censored 150s rsync cell so the
resumed run re-measures them with the larger timeout."""
import json, collections, shutil, os, sys

_bench_root = os.environ.get("BENCH_ROOT", os.path.join(os.path.expanduser("~"), "aft-bench"))
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_bench_root, "results.jsonl")
shutil.copy(p, p.replace(".jsonl", ".partial.bak"))
rows = [json.loads(l) for l in open(p) if l.strip()]
cnt = collections.Counter((r["regime"], r["workload"], r["tool"]) for r in rows)
drop = {k for k, v in cnt.items() if v < 3}
drop.add(("good", "single_500m", "rsync"))
kept = [r for r in rows if (r["regime"], r["workload"], r["tool"]) not in drop]
open(p, "w").write("".join(json.dumps(r) + "\n" for r in kept))
print("dropped cells:", sorted(drop))
print("kept", len(kept), "of", len(rows), "rows")
