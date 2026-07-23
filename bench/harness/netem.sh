#!/bin/bash
# netem.sh -- two-namespace veth testbed with named impairment regimes.
#
#   ns_a (client/sender) 10.0.0.1  <--veth-->  10.0.0.2 ns_b (server/receiver)
#
# Impairments are applied to the EGRESS of both veth ends, which makes them
# bidirectional (each direction traverses exactly one impaired egress qdisc).
#
# Usage:
#   ./netem.sh up                 # create namespaces + link, no impairment
#   ./netem.sh regime <name>      # apply one of: perfect good bad broken
#   ./netem.sh reset              # strip all qdiscs (link stays up)
#   ./netem.sh down               # tear everything down
#   ./netem.sh show
set -euo pipefail

NS_A=ns_a
NS_B=ns_b
IF_A=veth_a
IF_B=veth_b
IP_A=10.0.0.1
IP_B=10.0.0.2
PFX=24

# Regime table -- matches ATP's published regimes exactly.
#   name : rate : netem-args
regime_rate() {
  case "$1" in
    perfect) echo "1gbit" ;;
    good)    echo "200mbit" ;;
    bad)     echo "50mbit" ;;
    broken)  echo "10mbit" ;;
    *) echo "unknown regime: $1" >&2; exit 2 ;;
  esac
}
regime_netem() {
  case "$1" in
    perfect) echo "delay 2ms loss 0%" ;;
    good)    echo "delay 25ms loss 0.1%" ;;
    bad)     echo "delay 80ms 20ms loss 2%" ;;
    broken)  echo "delay 200ms 50ms loss 10% reorder 5% duplicate 1%" ;;
    *) echo "unknown regime: $1" >&2; exit 2 ;;
  esac
}

up() {
  down >/dev/null 2>&1 || true
  ip netns add $NS_A
  ip netns add $NS_B
  ip link add $IF_A type veth peer name $IF_B
  ip link set $IF_A netns $NS_A
  ip link set $IF_B netns $NS_B
  ip netns exec $NS_A ip addr add $IP_A/$PFX dev $IF_A
  ip netns exec $NS_B ip addr add $IP_B/$PFX dev $IF_B
  ip netns exec $NS_A ip link set $IF_A up
  ip netns exec $NS_B ip link set $IF_B up
  ip netns exec $NS_A ip link set lo up
  ip netns exec $NS_B ip link set lo up
  # Generous txqueuelen so the shaper, not the device ring, is the bottleneck.
  ip netns exec $NS_A ip link set $IF_A txqueuelen 10000
  ip netns exec $NS_B ip link set $IF_B txqueuelen 10000
  # Generous socket buffers so no tool is accidentally starved of window on the
  # high-BDP regimes. net.core.* is NOT network-namespaced on this kernel, so it
  # is set globally; net.ipv4.tcp_* is namespaced and set per-ns.
  sysctl -q -w net.core.rmem_max=134217728
  sysctl -q -w net.core.wmem_max=134217728
  for ns in $NS_A $NS_B; do
    ip netns exec $ns sysctl -q -w net.ipv4.tcp_rmem="4096 87380 134217728"
    ip netns exec $ns sysctl -q -w net.ipv4.tcp_wmem="4096 65536 134217728"
    ip netns exec $ns sysctl -q -w net.ipv4.tcp_congestion_control=cubic
  done
}

reset_qdisc() {
  ip netns exec $NS_A tc qdisc del dev $IF_A root 2>/dev/null || true
  ip netns exec $NS_B tc qdisc del dev $IF_B root 2>/dev/null || true
}

apply_one() {
  local ns=$1 dev=$2 rate=$3 netem=$4
  # htb shapes to the regime rate; netem hangs off the leaf class and adds
  # delay/jitter/loss/reorder/duplication.
  # r2q 2000 keeps htb's derived quantum sane at 1gbit (avoids the
  # "quantum of class is big" warning and the scheduling inaccuracy behind it).
  ip netns exec $ns tc qdisc add dev $dev root handle 1: htb default 10 r2q 2000
  ip netns exec $ns tc class add dev $dev parent 1: classid 1:10 \
      htb rate $rate ceil $rate burst 32k
  # limit 200000 packets: must exceed bandwidth-delay product or netem itself
  # becomes the drop source and silently corrupts the loss figure.
  ip netns exec $ns tc qdisc add dev $dev parent 1:10 handle 10: \
      netem limit 200000 $netem
}

regime() {
  local name=$1
  local rate netem
  rate=$(regime_rate "$name")
  netem=$(regime_netem "$name")
  reset_qdisc
  apply_one $NS_A $IF_A "$rate" "$netem"
  apply_one $NS_B $IF_B "$rate" "$netem"
  echo "regime=$name rate=$rate netem='$netem' (both directions)"
}

down() {
  ip netns del $NS_A 2>/dev/null || true
  ip netns del $NS_B 2>/dev/null || true
}

show() {
  echo "--- $NS_A/$IF_A ---"; ip netns exec $NS_A tc qdisc show dev $IF_A || true
  echo "--- $NS_B/$IF_B ---"; ip netns exec $NS_B tc qdisc show dev $IF_B || true
}

case "${1:-}" in
  up) up ;;
  regime) regime "${2:?regime name required}" ;;
  reset) reset_qdisc ;;
  down) down ;;
  show) show ;;
  *) echo "usage: $0 {up|regime <perfect|good|bad|broken>|reset|down|show}" >&2; exit 2 ;;
esac
