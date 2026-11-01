#!/usr/bin/env bash
# End-to-end mesh gate: bring up the four-node internal dual-stack network, wait
# for discovery, and assert via tierctl that every node sees the whole mesh and
# advertises both address families. Tears the network down on exit. Non-zero
# exit means the mesh did not converge - intended to gate a release/deploy.
#
# Env:
#   DISCOVERY_TIMEOUT   seconds to wait for convergence (default 30; 5 is usually
#                       enough, the ceiling only guards slow CI).
#   REQUIRE_DUALSTACK   1 (default) also asserts each node advertises IPv4+IPv6;
#                       0 asserts discovery only.
#   TIERD_BIN/TIERCTL_BIN  reuse prebuilt binaries (passed through to build.sh).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-e2e"
nodes="node1 node2 node3 node4"
expected_known=4   # each node counts itself plus the three others
min_connected=3    # a converged node holds a live connection to the other three
discovery_timeout="${DISCOVERY_TIMEOUT:-30}"
require_dualstack="${REQUIRE_DUALSTACK:-1}"

compose() { docker compose -p "$project" "$@"; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$here/build.sh"

echo "== bringing up 4-node internal mesh =="
compose up -d

# known= / connected= from a node's tierctl, or "0 0" if it is not answering yet.
peers_counts() {
  local out
  out="$(compose exec -T "$1" tierctl peers 2>/dev/null || true)"
  local known connected
  known="$(printf '%s\n' "$out" | sed -n 's/^known=\([0-9]*\).*/\1/p')"
  connected="$(printf '%s\n' "$out" | sed -n 's/.*connected=\([0-9]*\).*/\1/p')"
  printf '%s %s\n' "${known:-0}" "${connected:-0}"
}

echo "== waiting up to ${discovery_timeout}s for convergence =="
start=$(date +%s)
while :; do
  all_ok=1
  for n in $nodes; do
    read -r known connected <<<"$(peers_counts "$n")"
    if [ "$known" != "$expected_known" ] || [ "$connected" -lt "$min_connected" ]; then
      all_ok=0
    fi
  done
  now=$(date +%s)
  if [ "$all_ok" = 1 ]; then
    echo "converged in $((now - start))s"
    break
  fi
  if [ "$((now - start))" -ge "$discovery_timeout" ]; then
    echo "did not converge within ${discovery_timeout}s"
    break
  fi
  sleep 1
done

echo
echo "== final view per node =="
failures=0
for n in $nodes; do
  out="$(compose exec -T "$n" tierctl peers 2>/dev/null || true)"
  echo "---- $n ----"
  printf '%s\n' "$out"

  read -r known connected <<<"$(peers_counts "$n")"
  if [ "$known" != "$expected_known" ]; then
    echo "FAIL: $n known=$known, expected $expected_known"
    failures=$((failures + 1))
  fi
  if [ "$connected" -lt "$min_connected" ]; then
    echo "FAIL: $n connected=$connected, expected >= $min_connected"
    failures=$((failures + 1))
  fi

  if [ "$require_dualstack" = 1 ]; then
    # Every peer row (any line with a :7777 address) must carry both an IPv6
    # (bracketed) and an IPv4 address, i.e. the node advertises both families.
    while IFS= read -r line; do
      case "$line" in
        *:7777*) ;;
        *) continue ;;
      esac
      has_v6=0; has_v4=0
      case "$line" in *"["*) has_v6=1 ;; esac
      if printf '%s\n' "$line" | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:7777'; then
        has_v4=1
      fi
      if [ "$has_v6" != 1 ] || [ "$has_v4" != 1 ]; then
        echo "FAIL: $n has a single-family peer row: $line"
        failures=$((failures + 1))
      fi
    done <<EOF
$out
EOF
  fi
done

echo
if [ "$failures" -eq 0 ]; then
  if [ "$require_dualstack" = 1 ]; then
    echo "e2e OK: all nodes discovered the full mesh (dual-stack verified)"
  else
    echo "e2e OK: all nodes discovered the full mesh"
  fi
  exit 0
fi
echo "e2e FAILED: $failures check(s) failed"
exit 1
