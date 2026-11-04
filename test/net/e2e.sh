#!/usr/bin/env bash
# End-to-end mesh gate: bring up the four-node internal dual-stack network, wait
# for discovery, and assert via tierctl that every node sees the whole mesh and
# advertises both address families. Then exercise the encrypted-messaging path
# on the live mesh: node1 sends node2 a sealed message in each crypto suite and
# node2 must receive all three intact. Tears the network down on exit. Non-zero
# exit means the mesh did not converge or a message did not arrive - intended to
# gate a release/deploy.
#
# Env:
#   DISCOVERY_TIMEOUT   seconds to wait for convergence (default 30; 5 is usually
#                       enough, the ceiling only guards slow CI).
#   REQUIRE_DUALSTACK   1 (default) also asserts each node advertises IPv4+IPv6;
#                       0 asserts discovery only.
#   REQUIRE_MESSAGING   1 (default) also runs the encrypted send/inbox leg; 0
#                       skips it (mesh/dual-stack checks only).
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
require_messaging="${REQUIRE_MESSAGING:-1}"
message_timeout="${MESSAGE_TIMEOUT:-15}"   # seconds to wait for all three to arrive

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
  known="$(printf '%s\n' "$out" | sed -n 's/.*known=\([0-9]*\).*/\1/p')"
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

# --- messaging leg: encrypted send/inbox across the live mesh ---
# Proves the real on-wire sealed-message path on the shipping binary. node1
# sends node2 one encrypted message per crypto suite (classical, hybrid, pq);
# node2 drains its inbox and must receive all three with intact plaintext and
# the matching suite tag. Delivery v1 is direct, so this relies on node1 holding
# a live connection to node2 (guaranteed by the convergence gate above, which
# requires each node connected to the other three).
if [ "$require_messaging" = 1 ]; then
  echo
  echo "== messaging leg: encrypted send/inbox (node1 -> node2) =="

  # node2's full 64-hex device id (tierctl peers only shows a truncated id;
  # tierctl id prints a "device <hex>" line and a "user <hex|->" line).
  recipient="$(compose exec -T node2 tierctl id 2>/dev/null \
    | sed -n 's/^device *\([0-9a-f]\{64\}\).*/\1/p' | head -n1 || true)"

  if [ -z "$recipient" ]; then
    echo "FAIL: could not determine node2 peer id from its startup log"
    failures=$((failures + 1))
  else
    echo "recipient (node2) = $recipient"
    stamp="$(date +%s)"
    suites="classical hybrid pq"

    marker_for() { printf 'e2e-%s-%s' "$1" "$stamp"; }

    for suite in $suites; do
      if compose exec -T node1 tierctl send "$recipient" "$suite" "$(marker_for "$suite")"; then
        echo "node1 sent $suite"
      else
        echo "FAIL: node1 could not send $suite to node2"
        failures=$((failures + 1))
      fi
    done

    # Delivery is asynchronous and `tierctl inbox` drains on each read, so
    # accumulate what each poll returns until all three markers appear or we
    # time out.
    inbox_acc=""
    deadline=$(( $(date +%s) + message_timeout ))
    while :; do
      got="$(compose exec -T node2 tierctl inbox 2>/dev/null || true)"
      inbox_acc="$inbox_acc
$got"
      have_all=1
      for suite in $suites; do
        printf '%s\n' "$inbox_acc" | grep -q "$(marker_for "$suite")" || have_all=0
      done
      [ "$have_all" = 1 ] && break
      [ "$(date +%s)" -ge "$deadline" ] && break
      sleep 1
    done

    echo "---- node2 inbox (accumulated) ----"
    printf '%s\n' "$inbox_acc" | grep -E 'message\(s\)|^from ' || true

    # Each message must land on its own suite line with the exact marker text,
    # which ties the decrypted plaintext to the suite it was sealed with.
    for suite in $suites; do
      if printf '%s\n' "$inbox_acc" | grep -q "suite=$suite.*$(marker_for "$suite")"; then
        echo "node2 received $suite"
      else
        echo "FAIL: node2 did not receive an intact $suite message"
        failures=$((failures + 1))
      fi
    done
  fi
fi

echo
if [ "$failures" -eq 0 ]; then
  summary="e2e OK: all nodes discovered the full mesh"
  [ "$require_dualstack" = 1 ] && summary="$summary (dual-stack verified)"
  [ "$require_messaging" = 1 ] && summary="$summary; encrypted messaging delivered (3 suites)"
  echo "$summary"
  exit 0
fi
echo "e2e FAILED: $failures check(s) failed"
exit 1
