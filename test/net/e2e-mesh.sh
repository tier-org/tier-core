#!/usr/bin/env bash
# Production-shaped cross-node delivery + receipt gate (see docs/multi-identity.md,
# docs/app-protocol.md). Three ALL-ROLE nodes in a full mesh, each hosting one
# user id created at runtime (`tierctl user add <seed>`, distinct seed per node).
# Unlike the star gates (e2e-multi/e2e-roles: dedicated communicators + edge
# clients), every node here is simultaneously communicator, meshing infrastructure
# peer, and user host - exactly the deployed topology in which messages flowed
# one way but not the other and delivery receipts went missing.
#
# Each node subscribes to its own user (`tierctl stream <user>`, detached) BEFORE
# any send, because user messages are online-only (delivered to a live subscriber,
# never buffered). The harness then sends across EVERY ordered node pair. It
# asserts two things the star gates cannot:
#   1. delivery in BOTH directions for every pair, attributed to the right sender
#      user and addressed to the right recipient user;
#   2. a delivery receipt returning to each SENDER for every message it sent.
# A one-directional loss or a missing receipt (the reproduced prod bug) fails the
# gate. Non-zero exit means discovery, delivery, or the receipt path failed.
#
# Env:
#   CONVERGE_TIMEOUT   seconds to wait for the mesh to form (default 40).
#   MESSAGE_TIMEOUT    seconds to wait for all messages to land (default 40).
#   SETTLE_SECONDS     seconds to let user enrollments converge (default 12).
#   TIERD_BIN/TIERCTL_BIN  reuse prebuilt binaries (passed through to build.sh).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-mesh-e2e"
compose_file="docker-compose.mesh.yml"
converge_timeout="${CONVERGE_TIMEOUT:-40}"
message_timeout="${MESSAGE_TIMEOUT:-40}"
# Each node must host its user AND enroll it with the responsible communicators
# (which may be remote nodes) before a cross-node send can resolve. Rendezvous
# spreads responsibility across all three nodes, so give enrollment time to reach
# the responsible peers after the mesh forms.
settle_seconds="${SETTLE_SECONDS:-12}"

nodes="node1 node2 node3"

compose() { docker compose -p "$project" -f "$compose_file" "$@"; }

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$here/build.sh"

echo "== bringing up 3 all-role nodes (full mesh) =="
compose up -d

connected_count() {
  local out
  out="$(compose exec -T "$1" tierctl peers 2>/dev/null || true)"
  printf '%s\n' "$out" | sed -n 's/.*connected=\([0-9]*\).*/\1/p' | head -n1
}

# A fresh 32-byte Ed25519 seed as 64 lowercase hex chars.
random_seed_hex() { head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n'; }

# `tierctl user add <seed>` prints "user <64hex>"; extract that id.
add_user() {  # $1 = service, $2 = seed hex -> prints user id
  compose exec -T "$1" tierctl user add "$2" 2>/dev/null \
    | sed -n 's/^user \([0-9a-f]\{64\}\).*/\1/p' | head -n1
}

# Start a detached `tierctl stream <user>` inside a container, capturing its
# output to a file there. The subscription must exist before any send.
start_stream() {  # $1 = service, $2 = user id
  compose exec -d "$1" sh -c "tierctl stream $2 > /tmp/stream.log 2>&1"
}
read_stream() {  # $1 = service -> prints captured stream so far
  compose exec -T "$1" cat /tmp/stream.log 2>/dev/null || true
}

echo "== waiting up to ${converge_timeout}s for the mesh to form (each node >=2 peers) =="
start=$(date +%s)
while :; do
  ok=1
  summary=""
  for n in $nodes; do
    c="$(connected_count "$n")"
    summary="$summary $n=${c:-0}"
    [ "${c:-0}" -ge 2 ] || ok=0
  done
  if [ "$ok" = 1 ]; then
    echo "meshed in $(( $(date +%s) - start ))s ($summary )"
    break
  fi
  if [ "$(( $(date +%s) - start ))" -ge "$converge_timeout" ]; then
    echo "did not mesh:$summary"
    compose logs --tail=40 || true
    exit 1
  fi
  sleep 1
done

# Create one user per node (distinct seeds) and remember them by index.
declare -A user_of
for n in $nodes; do
  uid="$(add_user "$n" "$(random_seed_hex)")"
  if [ -z "$uid" ]; then
    echo "FAIL: $n could not create its user identity"
    exit 1
  fi
  user_of[$n]="$uid"
  echo "$n hosts user ${uid:0:16}"
done

# Subscribe every node to its own user before sending: user messages are
# delivered only to a live subscriber, and the receipt for an outbound send is
# delivered to the sender's own live subscriber.
for n in $nodes; do
  start_stream "$n" "${user_of[$n]}"
done

# Let the user enrollments settle on the responsible communicators.
sleep "$settle_seconds"

suite="hybrid"
stamp="$(date +%s)"
# Unique marker for an ordered (sender,recipient) pair.
marker_for() { printf 'mesh-%s-to-%s-%s' "$1" "$2" "$stamp"; }

failures=0
declare -A sent_count
for n in $nodes; do sent_count[$n]=0; done

echo "== sending across every ordered node pair =="
for s in $nodes; do
  for r in $nodes; do
    [ "$s" = "$r" ] && continue
    if compose exec -T "$s" \
         tierctl send-user "${user_of[$s]}" "${user_of[$r]}" "$suite" \
         "$(marker_for "$s" "$r")"; then
      echo "$s -> $r accepted"
      sent_count[$s]=$(( sent_count[$s] + 1 ))
    else
      echo "FAIL: $s could not accept send-user to $r"
      failures=$((failures + 1))
    fi
  done
done

# Wait until each recipient's stream shows every marker addressed to it, or we
# time out.
wait_for_delivery() {  # $1 = recipient service
  local r="$1" got deadline
  deadline=$(( $(date +%s) + message_timeout ))
  while :; do
    got="$(read_stream "$r")"
    local have_all=1
    for s in $nodes; do
      [ "$s" = "$r" ] && continue
      printf '%s\n' "$got" | grep -q "$(marker_for "$s" "$r")" || have_all=0
    done
    [ "$have_all" = 1 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 1
  done
}

echo "== verifying delivery (both directions, attributed) =="
for r in $nodes; do
  wait_for_delivery "$r"
  acc="$(read_stream "$r")"
  r_short="${user_of[$r]:0:16}"
  for s in $nodes; do
    [ "$s" = "$r" ] && continue
    s_short="${user_of[$s]:0:16}"
    m="$(marker_for "$s" "$r")"
    # The delivered line must carry the marker, be addressed to this recipient
    # user, and be attributed to the sending user.
    if printf '%s\n' "$acc" \
         | grep -q "from user ${s_short}.*to-user ${r_short}.*${m}"; then
      echo "$r received from $s (attributed)"
    else
      echo "FAIL: $r did not receive an attributed message from $s"
      failures=$((failures + 1))
    fi
  done
done

# Every sender must get one delivery receipt back per message it sent. This is
# the assertion the star gates approximate (>=1) but here it must hold for every
# ordered pair across the all-role mesh.
echo "== verifying delivery receipts (one per sent message, per sender) =="
for s in $nodes; do
  acc="$(read_stream "$s")"
  got="$(printf '%s\n' "$acc" | grep -c '^receipt ' || true)"
  want="${sent_count[$s]}"
  if [ "${got:-0}" -ge "$want" ]; then
    echo "$s received $got receipt(s) (sent $want)"
  else
    echo "FAIL: $s received $got receipt(s) but sent $want"
    failures=$((failures + 1))
  fi
done

echo
if [ "$failures" -eq 0 ]; then
  echo "mesh e2e OK: all-role nodes delivered across every ordered pair in both"
  echo "directions, attributed correctly, and every sender saw its receipts"
  exit 0
fi
echo "mesh e2e FAILED: $failures check(s) failed"
exit 1
