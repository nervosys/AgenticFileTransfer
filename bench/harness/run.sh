#!/bin/bash
# run.sh -- head-to-head transfer benchmark: rsync vs atp vs aft.
#
# Every tool PUSHES from ns_a (client) to a server in ns_b, across the veth
# link impaired by netem.sh. Wall clock is measured around the client process;
# peak RSS comes from /usr/bin/time -v on that same client process (its rusage
# aggregates reaped descendants).
#
# Results stream to results.jsonl as they are produced so a crash or a manual
# abort still leaves usable data; report.py folds them into results.json.
set -u

H=/root/bench/harness
DATA=/root/bench/data
DST=/root/bench/dst
LOGS=/root/bench/logs
OUT=${OUT:-/root/bench/results.jsonl}

AFT=/root/bench/aft-src/target/release/aft
ATP=/home/test/bench/asupersync/target/release/atp

IP_B=10.0.0.2
RSYNC_PORT=8730
ATP_PORT=8472
AFT_PORT=2600

RUNS=${RUNS:-3}

mkdir -p "$LOGS"
# RESUME=1 appends to an existing results file and skips any (regime, workload,
# tool) cell that already has a full set of RUNS rows, so an interrupted
# benchmark can be continued without re-measuring completed cells.
RESUME=${RESUME:-0}
[ "$RESUME" = 1 ] || : > "$OUT"
touch "$OUT"

cell_done() { # regime workload tool -- true if RUNS rows already recorded
  [ "$RESUME" = 1 ] || return 1
  local n
  n=$(python3 - "$OUT" "$1" "$2" "$3" <<'PY'
import json,sys
p,regime,wl,tool=sys.argv[1:5]
n=0
for line in open(p):
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    if d["regime"]==regime and d["workload"]==wl and d["tool"]==tool: n+=1
print(n)
PY
)
  [ "$n" -ge "$RUNS" ]
}

# ---------------------------------------------------------------- matrix ----
# Workloads per regime. The high-impairment regimes carry a reduced set: at
# 10mbit/400ms RTT/10% loss a 500MB transfer cannot finish inside any sane
# budget, so it is deliberately excluded rather than left to time out.
regime_workloads() {
  case "$1" in
    perfect) echo "small_500k single_50m single_500m tree_2000x1k tree_400x1m" ;;
    good)    echo "small_500k single_50m single_500m tree_2000x1k tree_400x1m" ;;
    bad)     echo "small_500k single_50m tree_2000x1k" ;;
    broken)  echo "small_500k tree_2000x1k" ;;
  esac
}
regime_timeout() {
  # TIMEOUT_OVERRIDE lets a resumed run use a much larger cap so that slow-but-
  # finishing transfers yield a real number instead of a censored one.
  if [ -n "${TIMEOUT_OVERRIDE:-}" ]; then echo "$TIMEOUT_OVERRIDE"; return; fi
  case "$1" in
    perfect) echo 120 ;; good) echo 150 ;; bad) echo 90 ;; broken) echo 120 ;;
  esac
}
is_tree() { case "$1" in tree_*) return 0 ;; *) return 1 ;; esac; }

TOOLS=${TOOLS:-"rsync atp-tcp atp-rq aft aft-turbo"}

# ---------------------------------------------------------------- helpers ---
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

emit() { # tool workload regime run status secs rss_kb bytes note
  python3 - "$@" <<'PY' >> "$OUT"
import json,sys
k=["tool","workload","regime","run","status","seconds","rss_kb","bytes","note"]
v=sys.argv[1:10]
d=dict(zip(k,v))
for n in ("run","rss_kb","bytes"):
    try: d[n]=int(d[n])
    except Exception: d[n]=None
try: d["seconds"]=float(d["seconds"])
except Exception: d["seconds"]=None
print(json.dumps(d))
PY
}

wait_port() { # port maxsec -- wait until ns_b is LISTENing on the port.
  # Must NOT be a connect probe: `atp recv --once` treats the first accepted
  # connection as the transfer, so dialing it would consume the receiver and
  # every subsequent real client would get ECONNREFUSED.
  local port=$1 max=$2 t=0
  while [ "$(echo "$t < $max" | bc)" = 1 ]; do
    if ip netns exec ns_b ss -ltnH 2>/dev/null | grep -q ":$port\b"; then
      sleep 0.2   # small grace for the accept loop to arm
      return 0
    fi
    sleep 0.2; t=$(echo "$t + 0.2" | bc)
  done
  return 1
}

kill_servers() {
  pkill -f "rsync --daemon" 2>/dev/null
  pkill -f "$ATP recv" 2>/dev/null
  pkill -f "$AFT serve" 2>/dev/null
  sleep 0.3
}

dst_bytes() { find "$DST" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'; }
src_bytes() { find "$1" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'; }

cat > /root/bench/rsyncd.conf <<EOF
uid = root
gid = root
use chroot = no
max connections = 8
pid file = /root/bench/rsyncd.pid
lock file = /root/bench/rsyncd.lock
log file = /root/bench/rsyncd.log
[data]
  path = $DST
  read only = false
EOF

# ------------------------------------------------------------- one measure --
# Runs one (tool, workload, regime, run) and appends a result line.
measure() {
  local tool=$1 wl=$2 regime=$3 run=$4
  local src="$DATA/$wl"
  local tmo; tmo=$(regime_timeout "$regime")
  # Sum of regular-file bytes only -- `du -sb` would also count directory
  # inodes, which the destination-side tally does not.
  local expect; expect=$(src_bytes "$src")
  local tag="$regime.$wl.$tool.$run"
  local tf="$LOGS/$tag.time" sl="$LOGS/$tag.server" cl="$LOGS/$tag.client"


  kill_servers
  rm -rf "$DST"; mkdir -p "$DST"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

  local client_cmd=() port=
  case "$tool" in
    rsync)
      port=$RSYNC_PORT
      ip netns exec ns_b rsync --daemon --config=/root/bench/rsyncd.conf \
        --port $RSYNC_PORT --no-detach >"$sl" 2>&1 &
      client_cmd=(rsync -a --port $RSYNC_PORT "$src/" "rsync://$IP_B/data/")
      ;;
    atp-tcp)
      port=$ATP_PORT
      ip netns exec ns_b "$ATP" recv "$DST" --listen 0.0.0.0:$ATP_PORT --once \
        --transport tcp --accept-timeout-secs $tmo >"$sl" 2>&1 &
      client_cmd=("$ATP" send "$src" "$IP_B:$ATP_PORT" --transport tcp)
      ;;
    atp-rq)
      port=$ATP_PORT
      ip netns exec ns_b "$ATP" recv "$DST" --listen 0.0.0.0:$ATP_PORT --once \
        --transport rq --rq-allow-unauthenticated-lab \
        --accept-timeout-secs $tmo >"$sl" 2>&1 &
      client_cmd=("$ATP" send "$src" "$IP_B:$ATP_PORT" --transport rq \
        --rq-allow-unauthenticated-lab)
      ;;
    aft|aft-turbo|aft-fec)
      port=$AFT_PORT
      ip netns exec ns_b "$AFT" serve "$DST" --bind 0.0.0.0 --port $AFT_PORT \
        >"$sl" 2>&1 &
      local turbo=()
      [ "$tool" = aft-turbo ] && turbo=(--turbo)
      [ "$tool" = aft-fec ] && turbo=(--fec)
      if is_tree "$wl"; then
        client_cmd=("$AFT" "${turbo[@]}" copy -r "$src" "aftp://$IP_B:$AFT_PORT/")
      else
        local f; f=$(find "$src" -type f | head -1)
        client_cmd=("$AFT" "${turbo[@]}" copy "$f" "aftp://$IP_B:$AFT_PORT/$(basename "$f")")
      fi
      ;;
  esac

  if ! wait_port "$port" 15; then
    emit "$tool" "$wl" "$regime" "$run" error "" "" "" "server did not accept connections on port $port within 15s"
    kill_servers; return
  fi

  local t0 t1 secs rc
  t0=$EPOCHREALTIME
  timeout "$tmo" /usr/bin/time -v -o "$tf" \
    ip netns exec ns_a "${client_cmd[@]}" >"$cl" 2>&1
  rc=$?
  t1=$EPOCHREALTIME
  secs=$(echo "$t1 - $t0" | bc)

  local rss; rss=$(awk -F': ' '/Maximum resident set size/{print $2}' "$tf" 2>/dev/null)
  local got; got=$(dst_bytes)
  kill_servers

  if [ $rc -eq 124 ]; then
    emit "$tool" "$wl" "$regime" "$run" timeout "$secs" "${rss:-}" "$got" "exceeded ${tmo}s timeout"
  elif [ $rc -ne 0 ]; then
    emit "$tool" "$wl" "$regime" "$run" error "$secs" "${rss:-}" "$got" \
      "client exit $rc: $(tail -c 400 "$cl" | tr '\n' ' ')"
  elif [ "$got" != "$expect" ]; then
    emit "$tool" "$wl" "$regime" "$run" mismatch "$secs" "${rss:-}" "$got" \
      "transferred $got bytes, expected $expect"
  else
    emit "$tool" "$wl" "$regime" "$run" ok "$secs" "${rss:-}" "$got" ""
  fi
  printf '%-8s %-8s %-14s %-10s run%-2s %8ss rc=%s\n' \
    "$regime" "$tool" "$wl" "" "$run" "$secs" "$rc" >&2
}

# -------------------------------------------------------------------- main --
$H/netem.sh up
trap '$H/netem.sh down' EXIT

BENCH_T0=$EPOCHREALTIME
for regime in ${REGIMES:-perfect good bad broken}; do
  $H/netem.sh regime "$regime" >&2
  for wl in ${WORKLOADS:-$(regime_workloads "$regime")}; do
    for tool in $TOOLS; do
      if cell_done "$regime" "$wl" "$tool"; then
        echo "skip (already recorded): $regime $wl $tool" >&2
        continue
      fi
      for run in $(seq 1 $RUNS); do
        measure "$tool" "$wl" "$regime" "$run"
      done
    done
  done
  echo "### regime $regime done, elapsed $(echo "$EPOCHREALTIME - $BENCH_T0" | bc)s" >&2
done
$H/netem.sh reset
echo "raw results: $OUT" >&2
