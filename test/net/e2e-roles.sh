#!/usr/bin/env bash
# Client-to-client discovery gate (see docs/communicator.md). Brings up a mesh
# of two communicators and two plain clients, waits for the clients to attach to
# the communicators, then has client A send client B an encrypted message in
# each suite. The two clients share no direct connection and never gossip each
# other, so delivery proves the full path: B publishes a presence record to a
# communicator, A resolves B by a presence lookup, connects directly, and the
# sealed message arrives. Non-zero exit means discovery or delivery failed.
#
# Env:
#   CONVERGE_TIMEOUT   seconds to wait for the clients to attach (default 40).
#   MESSAGE_TIMEOUT    seconds to wait for all three messages (default 20).
#   TIERD_BIN/TIERCTL_BIN  reuse prebuilt binaries (passed through to build.sh).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-roles-e2e"
compose_file="docker-compose.roles.yml"
converge_timeout="${CONVERGE_TIMEOUT:-40}"
message_timeout="${MESSAGE_TIMEOUT:-20}"

compose() { docker compose -p "$project" -f "$compose_file" "$@"; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$here/build.sh"

echo "== bringing up 2 communicators + 2 clients =="
compose up -d

# connected= count from a service's tierctl, or 0 if it is not answering yet.
connected_count() {
  local out
  out="$(compose exec -T "$1" tierctl peers 2>/dev/null || true)"
  printf '%s\n' "$out" | sed -n 's/.*connected=\([0-9]*\).*/\1/p' | head -n1
}

echo "== waiting up to ${converge_timeout}s for the clients to attach =="
start=$(date +%s)
while :; do
  ca="$(connected_count clienta)"; cb="$(connected_count clientb)"
  m1="$(connected_count comm1)"; m2="$(connected_count comm2)"
  if [ "${ca:-0}" -ge 1 ] && [ "${cb:-0}" -ge 1 ] && \
     [ "${m1:-0}" -ge 1 ] && [ "${m2:-0}" -ge 1 ]; then
    echo "attached in $(( $(date +%s) - start ))s (clienta=$ca clientb=$cb comm1=$m1 comm2=$m2)"
    break
  fi
  if [ "$(( $(date +%s) - start ))" -ge "$converge_timeout" ]; then
    echo "did not converge: clienta=${ca:-0} clientb=${cb:-0} comm1=${m1:-0} comm2=${m2:-0}"
    compose logs --tail=40 || true
    exit 1
  fi
  sleep 1
done

# Give presence registration a moment to reach the responsible communicator.
sleep 3

failures=0

# clientb's full 64-hex device id (tierctl id prints a "device <hex>" line).
recipient="$(compose exec -T clientb tierctl id 2>/dev/null \
  | sed -n 's/^device *\([0-9a-f]\{64\}\).*/\1/p' | head -n1 || true)"
if [ -z "$recipient" ]; then
  echo "FAIL: could not determine clientb peer id"
  exit 1
fi
echo "== client A -> client B ($recipient) via a communicator =="

stamp="$(date +%s)"
suites="classical hybrid pq"
marker_for() { printf 'roles-%s-%s' "$1" "$stamp"; }

for suite in $suites; do
  if compose exec -T clienta tierctl send "$recipient" "$suite" "$(marker_for "$suite")"; then
    echo "clienta sent $suite"
  else
    echo "FAIL: clienta could not accept the $suite send"
    failures=$((failures + 1))
  fi
done

# Accumulate clientb's inbox across polls (it drains on each read) until all
# three markers show up or we time out - discovery adds a lookup + dial round
# trip before the first message lands.
inbox_acc=""
deadline=$(( $(date +%s) + message_timeout ))
while :; do
  got="$(compose exec -T clientb tierctl inbox 2>/dev/null || true)"
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

echo "---- clientb inbox (accumulated) ----"
printf '%s\n' "$inbox_acc" | grep -E 'message\(s\)|^from ' || true

for suite in $suites; do
  if printf '%s\n' "$inbox_acc" | grep -q "suite=$suite.*$(marker_for "$suite")"; then
    echo "clientb received $suite"
  else
    echo "FAIL: clientb did not receive an intact $suite message"
    failures=$((failures + 1))
  fi
done

echo
if [ "$failures" -eq 0 ]; then
  echo "roles e2e OK: client-to-client discovery delivered (3 suites) with no prior connection"
  exit 0
fi
echo "roles e2e FAILED: $failures check(s) failed"
exit 1
