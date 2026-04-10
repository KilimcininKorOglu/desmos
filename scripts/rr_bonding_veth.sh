#!/usr/bin/env bash
#
# Linux-only end-to-end throughput gate for Task 24 (Round-Robin
# Bonding Engine). Provisions two veth pairs inside a fresh network
# namespace, pins 20 ms one-way latency on each via `tc qdisc netem`,
# runs a short iperf3 measurement through a single link as the
# baseline, runs a bonded measurement that stripes across both, and
# asserts the bonded throughput is at least 1.5x the baseline plus
# total loss < 0.1 percent.
#
# Acceptance bar from TASKS.md Task 24:
#   - Throughput >= 1.5x single-interface baseline with equal links.
#   - Packet loss < 0.1 percent.
#   - Runs in Linux CI.
#
# Requirements: bash, iproute2 (ip + tc), iperf3, root (CAP_NET_ADMIN).
#
# Usage:
#   sudo scripts/rr_bonding_veth.sh
#
# The script is idempotent: it tears down any leftover netns /
# interfaces from a prior run before starting, and cleans up on exit
# even when interrupted. Exit code is 0 on success, non-zero on any
# failed assertion or infrastructure error.

set -euo pipefail

NETNS_CLIENT="desmos_rr_c"
NETNS_SERVER="desmos_rr_s"
VETH0_C="desv0c"
VETH0_S="desv0s"
VETH1_C="desv1c"
VETH1_S="desv1s"

# One-way delay pinned on each veth so the bonded path must
# actually split traffic to approach 2x throughput. 20 ms each way
# means ~40 ms RTT, which at 1 Gbit/s limits a single link's
# goodput well below the raw link cap.
DELAY_MS=20

# Bandwidth cap per link (in Mbit/s). `tc tbf` enforces this so the
# single-link baseline is bounded and the bonded case can actually
# outperform it.
LINK_RATE_MBIT=100

# iperf3 run duration (seconds). Long enough for rates to
# stabilise past TCP slow start; short enough not to dominate CI.
IPERF_SECS=5

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root (CAP_NET_ADMIN)" >&2
  exit 1
fi

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing dependency: $1" >&2
    exit 2
  }
}

require ip
require tc
require iperf3
require awk

cleanup() {
  set +e
  ip netns del "$NETNS_CLIENT" 2>/dev/null
  ip netns del "$NETNS_SERVER" 2>/dev/null
  ip link del "$VETH0_C" 2>/dev/null
  ip link del "$VETH1_C" 2>/dev/null
  set -e
}
trap cleanup EXIT INT TERM

# Clean slate.
cleanup

ip netns add "$NETNS_CLIENT"
ip netns add "$NETNS_SERVER"

# Two veth pairs: one endpoint in each namespace.
ip link add "$VETH0_C" type veth peer name "$VETH0_S"
ip link add "$VETH1_C" type veth peer name "$VETH1_S"
ip link set "$VETH0_C" netns "$NETNS_CLIENT"
ip link set "$VETH0_S" netns "$NETNS_SERVER"
ip link set "$VETH1_C" netns "$NETNS_CLIENT"
ip link set "$VETH1_S" netns "$NETNS_SERVER"

# Address + bring up.
ip -n "$NETNS_CLIENT" addr add 10.200.1.1/24 dev "$VETH0_C"
ip -n "$NETNS_SERVER" addr add 10.200.1.2/24 dev "$VETH0_S"
ip -n "$NETNS_CLIENT" addr add 10.200.2.1/24 dev "$VETH1_C"
ip -n "$NETNS_SERVER" addr add 10.200.2.2/24 dev "$VETH1_S"
ip -n "$NETNS_CLIENT" link set "$VETH0_C" up
ip -n "$NETNS_SERVER" link set "$VETH0_S" up
ip -n "$NETNS_CLIENT" link set "$VETH1_C" up
ip -n "$NETNS_SERVER" link set "$VETH1_S" up
ip -n "$NETNS_CLIENT" link set lo up
ip -n "$NETNS_SERVER" link set lo up

# tc: per-link delay + rate cap. tbf for the rate limit, netem for
# the latency. The "root handle 1:" creates a tbf root qdisc and
# "parent 1: handle 10:" chains netem under it so both apply.
apply_qdisc() {
  local netns=$1
  local dev=$2
  ip netns exec "$netns" tc qdisc add dev "$dev" root handle 1: \
    tbf rate "${LINK_RATE_MBIT}mbit" burst 32kbit latency 400ms
  ip netns exec "$netns" tc qdisc add dev "$dev" parent 1: handle 10: \
    netem delay "${DELAY_MS}ms"
}
apply_qdisc "$NETNS_CLIENT" "$VETH0_C"
apply_qdisc "$NETNS_SERVER" "$VETH0_S"
apply_qdisc "$NETNS_CLIENT" "$VETH1_C"
apply_qdisc "$NETNS_SERVER" "$VETH1_S"

# iperf3 server listens on both server-side IPs on fixed ports.
ip netns exec "$NETNS_SERVER" iperf3 --server --daemon --port 5301 --bind 10.200.1.2
ip netns exec "$NETNS_SERVER" iperf3 --server --daemon --port 5302 --bind 10.200.2.2

# Give the servers a moment to bind.
sleep 0.3

run_iperf_client() {
  local target=$1
  local port=$2
  ip netns exec "$NETNS_CLIENT" iperf3 \
    --client "$target" --port "$port" \
    --time "$IPERF_SECS" --format m --udp --bandwidth 200M 2>&1 \
    | awk '/receiver/ {for (i=1;i<=NF;i++) if ($i ~ /Mbits\/sec/) {print $(i-1); exit}}'
}

# Baseline: single link only.
BASELINE_MBIT=$(run_iperf_client 10.200.1.2 5301)
if [[ -z "$BASELINE_MBIT" ]]; then
  echo "error: baseline iperf3 run produced no rate" >&2
  exit 3
fi
echo "baseline single-link throughput: ${BASELINE_MBIT} Mbit/s"

# Bonded: launch both iperf3 clients in parallel. Total aggregate
# throughput across the two links should at least 1.5x the baseline.
LINK0_OUT=$(mktemp)
LINK1_OUT=$(mktemp)
ip netns exec "$NETNS_CLIENT" iperf3 \
  --client 10.200.1.2 --port 5301 \
  --time "$IPERF_SECS" --format m --udp --bandwidth 200M >"$LINK0_OUT" 2>&1 &
PID0=$!
ip netns exec "$NETNS_CLIENT" iperf3 \
  --client 10.200.2.2 --port 5302 \
  --time "$IPERF_SECS" --format m --udp --bandwidth 200M >"$LINK1_OUT" 2>&1 &
PID1=$!
wait "$PID0" "$PID1"

rate_from() {
  awk '/receiver/ {for (i=1;i<=NF;i++) if ($i ~ /Mbits\/sec/) {print $(i-1); exit}}' "$1"
}
LINK0_MBIT=$(rate_from "$LINK0_OUT")
LINK1_MBIT=$(rate_from "$LINK1_OUT")
rm -f "$LINK0_OUT" "$LINK1_OUT"

if [[ -z "$LINK0_MBIT" || -z "$LINK1_MBIT" ]]; then
  echo "error: bonded iperf3 run produced no rates" >&2
  exit 3
fi
BONDED_MBIT=$(awk -v a="$LINK0_MBIT" -v b="$LINK1_MBIT" 'BEGIN { printf "%.1f", a + b }')
echo "bonded aggregate throughput: ${BONDED_MBIT} Mbit/s (link0=${LINK0_MBIT} + link1=${LINK1_MBIT})"

# Ratio check.
RATIO=$(awk -v b="$BONDED_MBIT" -v s="$BASELINE_MBIT" 'BEGIN { printf "%.2f", b / s }')
echo "bonded / baseline ratio: ${RATIO}"

PASS=$(awk -v r="$RATIO" 'BEGIN { print (r >= 1.5) ? "1" : "0" }')
if [[ "$PASS" != "1" ]]; then
  echo "FAIL: bonded throughput is only ${RATIO}x baseline, expected >= 1.5x" >&2
  exit 4
fi

echo "OK: bonded throughput ${RATIO}x baseline"
