#!/usr/bin/env bash
# Multi-identity gate (see docs/multi-identity.md, docs/app-protocol.md). Two
# communicators, two client "devices" that share one user identity, and a
# separate "sender" client with its own user identity. User identities are
# created at runtime over the admin socket (`tierctl user add <seed>`): the two
# devices import the same seed (so they host the one user id on two distinct
# devices), the sender imports its own.
#
# User messages are not buffered on a node (online-only); they are delivered to
# a live subscriber. So each device subscribes with `tierctl stream <user>`
# (detached, output captured in the container) BEFORE the send. The sender then
# sends from its user to the shared user id; both devices must receive every
# message, each showing the sender's user id and being addressed as the shared
# user, and the sender's own stream must show delivery receipts coming back.
# Non-zero exit means discovery, delivery, or the receipt path failed.
#
# Env:
#   CONVERGE_TIMEOUT   seconds to wait for the clients to attach (default 40).
#   MESSAGE_TIMEOUT    seconds to wait for all three messages (default 40).
#   TIERD_BIN/TIERCTL_BIN  reuse prebuilt binaries (passed through to build.sh).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-multi-e2e"
compose_file="docker-compose.multi.yml"
converge_timeout="${CONVERGE_TIMEOUT:-40}"
message_timeout="${MESSAGE_TIMEOUT:-40}"
# Both devices must host the user AND enroll it, and that must reach the
# responsible communicators, before a user send can resolve and fan out. That is
# more to converge than the single-recipient gates, so settle longer here.
settle_seconds="${SETTLE_SECONDS:-12}"

compose() { docker compose -p "$project" -f "$compose_file" "$@"; }

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$here/build.sh"

echo "== bringing up 2 communicators + 2 devices + sender =="
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

echo "== waiting up to ${converge_timeout}s for the clients to attach =="
start=$(date +%s)
while :; do
  da="$(connected_count devicea)"; db="$(connected_count deviceb)"
  sn="$(connected_count sender)"
  if [ "${da:-0}" -ge 1 ] && [ "${db:-0}" -ge 1 ] && [ "${sn:-0}" -ge 1 ]; then
    echo "attached in $(( $(date +%s) - start ))s (devicea=$da deviceb=$db sender=$sn)"
    break
  fi
  if [ "$(( $(date +%s) - start ))" -ge "$converge_timeout" ]; then
    echo "did not converge: devicea=${da:-0} deviceb=${db:-0} sender=${sn:-0}"
    compose logs --tail=40 || true
    exit 1
  fi
  sleep 1
done

# Create the user identities at runtime. The two devices import one shared seed
# (so they host the same user id); the sender imports its own.
shared_seed="$(random_seed_hex)"
sender_seed="$(random_seed_hex)"
ua="$(add_user devicea "$shared_seed")"
ub="$(add_user deviceb "$shared_seed")"
sender_user="$(add_user sender "$sender_seed")"
if [ -z "$ua" ] || [ "$ua" != "$ub" ]; then
  echo "FAIL: devices do not host one shared user id (devicea=$ua deviceb=$ub)"
  exit 1
fi
if [ -z "$sender_user" ]; then
  echo "FAIL: sender could not create its user identity"
  exit 1
fi
echo "shared user id = $ua"
echo "sender user id = $sender_user"

# Subscribe before sending: user messages are delivered only to a live
# subscriber. The sender subscribes too, to receive delivery receipts.
start_stream devicea "$ua"
start_stream deviceb "$ua"
start_stream sender "$sender_user"

# Let the user enrollments settle on the communicators.
sleep "$settle_seconds"

failures=0
stamp="$(date +%s)"
suites="classical hybrid pq"
marker_for() { printf 'multi-%s-%s' "$1" "$stamp"; }

for suite in $suites; do
  if compose exec -T sender \
       tierctl send-user "$sender_user" "$ua" "$suite" "$(marker_for "$suite")"; then
    echo "sender sent $suite from its user to the shared user"
  else
    echo "FAIL: sender could not accept the $suite send-user"
    failures=$((failures + 1))
  fi
done

# Wait until each device's stream shows all three markers, or we time out.
wait_for_markers() {  # $1 = service
  local got deadline
  deadline=$(( $(date +%s) + message_timeout ))
  while :; do
    got="$(read_stream "$1")"
    local have_all=1
    for suite in $suites; do
      printf '%s\n' "$got" | grep -q "$(marker_for "$suite")" || have_all=0
    done
    [ "$have_all" = 1 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 1
  done
}

for dev in devicea deviceb; do
  echo "---- $dev stream ----"
  wait_for_markers "$dev"
  acc="$(read_stream "$dev")"
  printf '%s\n' "$acc" | grep -E '^from ' || true
  for suite in $suites; do
    if printf '%s\n' "$acc" | grep -q "suite=$suite.*$(marker_for "$suite")"; then
      echo "$dev received $suite"
    else
      echo "FAIL: $dev did not receive an intact $suite message"
      failures=$((failures + 1))
    fi
  done
  # Each delivered message must show the sender's user id and be addressed to
  # the shared user.
  if printf '%s\n' "$acc" | grep -q "user ${sender_user:0:16}"; then
    echo "$dev saw the sender's user id"
  else
    echo "FAIL: $dev did not attribute the message to the sender's user"
    failures=$((failures + 1))
  fi
  if printf '%s\n' "$acc" | grep -q "to-user ${ua:0:16}"; then
    echo "$dev was addressed as the shared user"
  else
    echo "FAIL: $dev was not addressed as the shared user"
    failures=$((failures + 1))
  fi
done

# The sender's stream must show delivery receipts coming back (one per message
# the recipient's node delivered to a live subscriber).
echo "---- sender stream (receipts) ----"
sender_acc="$(read_stream sender)"
printf '%s\n' "$sender_acc" | grep -E '^receipt ' || true
receipts="$(printf '%s\n' "$sender_acc" | grep -c '^receipt ' || true)"
if [ "${receipts:-0}" -ge 1 ]; then
  echo "sender received $receipts delivery receipt(s)"
else
  echo "FAIL: sender received no delivery receipts"
  failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "multi-identity e2e OK: a user on two devices both received over the live"
  echo "stream, attributed to the sender's user, and the sender saw receipts"
  exit 0
fi
echo "multi-identity e2e FAILED: $failures check(s) failed"
exit 1
