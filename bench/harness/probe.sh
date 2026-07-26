#!/bin/bash
# probe.sh -- nail down the exact working invocation for each tool.
set -u
BENCH_ROOT=${BENCH_ROOT:-$HOME/aft-bench}
H=$BENCH_ROOT/harness
AFT=${AFT_BIN:-$BENCH_ROOT/aft-src/target/release/aft}
ATP=${ATP_BIN:-atp}
SRC=$BENCH_ROOT/probe_src
DST=$BENCH_ROOT/probe_dst

$H/netem.sh up
$H/netem.sh regime perfect >/dev/null

rm -rf $SRC $DST; mkdir -p $SRC $DST
head -c 3000000 /dev/urandom > $SRC/a.bin
mkdir -p $SRC/sub && head -c 100000 /dev/urandom > $SRC/sub/b.bin

banner() { echo; echo "################ $* ################"; }

banner RSYNC
cat > $BENCH_ROOT/rsyncd.conf <<EOF
uid = root
gid = root
use chroot = no
max connections = 8
pid file = $BENCH_ROOT/rsyncd.pid
lock file = $BENCH_ROOT/rsyncd.lock
log file = $BENCH_ROOT/rsyncd.log
[data]
  path = $DST
  read only = false
  write only = false
EOF
ip netns exec ns_b rsync --daemon --config=$BENCH_ROOT/rsyncd.conf --port 8730 --no-detach &
RPID=$!
sleep 1
ip netns exec ns_a rsync -a --port 8730 "$SRC/" rsync://10.0.0.2/data/
echo "rsync exit=$?"; find $DST -type f | sed 's/^/  /'
kill $RPID 2>/dev/null; wait $RPID 2>/dev/null

banner ATP-TCP
rm -rf $DST; mkdir -p $DST
ip netns exec ns_b $ATP recv $DST --listen 0.0.0.0:8472 --once --transport tcp &
APID=$!
sleep 1
ip netns exec ns_a $ATP send "$SRC" 10.0.0.2:8472 --transport tcp
echo "atp-tcp exit=$?"; wait $APID 2>/dev/null; find $DST -type f | sed 's/^/  /'

banner ATP-RQ
rm -rf $DST; mkdir -p $DST
ip netns exec ns_b $ATP recv $DST --listen 0.0.0.0:8472 --once --transport rq &
APID=$!
sleep 1
ip netns exec ns_a $ATP send "$SRC" 10.0.0.2:8472 --transport rq
echo "atp-rq exit=$?"; wait $APID 2>/dev/null; find $DST -type f | sed 's/^/  /'

banner AFT
rm -rf $DST; mkdir -p $DST
ip netns exec ns_b $AFT serve $DST --bind 0.0.0.0 --port 2600 &
FPID=$!
sleep 1
echo "--- try 1: copy -r dir -> aftp://host:port/ ---"
ip netns exec ns_a $AFT copy -r "$SRC" "aftp://10.0.0.2:2600/" ; echo "exit=$?"
find $DST -type f | sed 's/^/  /'
echo "--- try 2: copy single file -> aftp://host:port/a.bin ---"
ip netns exec ns_a $AFT copy "$SRC/a.bin" "aftp://10.0.0.2:2600/a.bin" ; echo "exit=$?"
find $DST -type f | sed 's/^/  /'
echo "--- try 3: sync dir -> aftp ---"
ip netns exec ns_a $AFT sync "$SRC" "aftp://10.0.0.2:2600/" ; echo "exit=$?"
find $DST -type f | sed 's/^/  /'
echo "--- try 4: aft ls aftp:// ---"
ip netns exec ns_a $AFT ls "aftp://10.0.0.2:2600/" ; echo "exit=$?"
kill $FPID 2>/dev/null
echo DONE
