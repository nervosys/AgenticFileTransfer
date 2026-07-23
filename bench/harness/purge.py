#!/usr/bin/env python3
"""Drop interrupted (partial) cells and the censored 150s rsync cell so the
resumed run re-measures them with the larger timeout."""
import json, collections, shutil

p = "/root/bench/results.jsonl"
shutil.copy(p, "/root/bench/results.partial.bak")
rows = [json.loads(l) for l in open(p) if l.strip()]
cnt = collections.Counter((r["regime"], r["workload"], r["tool"]) for r in rows)
drop = {k for k, v in cnt.items() if v < 3}
drop.add(("good", "single_500m", "rsync"))
kept = [r for r in rows if (r["regime"], r["workload"], r["tool"]) not in drop]
open(p, "w").write("".join(json.dumps(r) + "\n" for r in kept))
print("dropped cells:", sorted(drop))
print("kept", len(kept), "of", len(rows), "rows")
