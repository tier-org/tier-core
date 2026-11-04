#!/usr/bin/env bash
# Multi-identity gate (see docs/multi-identity.md). Two communicators, two client
# devices that share one user identity, and a separate sender with its own user
# identity. The sender addresses the shared user id; both devices must receive
# the message, each showing the sender's user id. No device has a prior
# connection to any other. Non-zero exit means discovery or delivery failed.
#
# Env:
#   CONVERGE_TIMEOUT   seconds to wait for the clients to attach (default 40).
#   MESSAGE_TIMEOUT    seconds to wait for all three messages (default 25).
#   TIERD_BIN/TIERCTL_BIN  reuse prebuilt binaries (passed through to build.sh).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-multi-e2e"
compose_file="docker-compose.multi.yml"
converge_timeout="${CONVERGE_TIMEOUT:-40}"
message_timeout="${MESSAGE_TIMEOUT:-40}"
# Both devices must register presence AND enroll under the user, and that must
# reach the responsible communicators, before a user send can resolve and fan
# out. That is more to converge than the single-recipient gates, so settle
# longer here.
settle_seconds="${SETTLE_SECONDS:-12}"

# Seed files for the shared user (both devices) and the sender's user. A random
# 32-byte file is a valid Ed25519 seed. Kept in a temp dir, removed on exit.
seed_dir="$(mktemp -d)"
export USER_SEED="$seed_dir/user.seed"
export SENDER_SEED="$seed_dir/sender.seed"
head -c 32 /dev/urandom > "$USER_SEED"
head -c 32 /dev/urandom > "$SENDER_SEED"
chmod 0644 "$USER_SEED" "$SENDER_SEED"

compose() { docker compose -p "$project" -f "$compose_file" "$@"; }

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$seed_dir"
}
trap cleanup EXIT

"$here/build.sh"

echo "== bringing up 2 communicators + 2 devices (shared user) + sender =="
compose up -d

connected_count() {
  local out
  out="$(compose exec -T "$1" tierctl peers 2>/dev/null || true)"
  printf '%s\n' "$out" | sed -n 's/.*connected=\([0-9]*\).*/\1/p' | head -n1
}

# The user id a service reports (from `tierctl id`, the "user <hex>" line).
user_id_of() {
  compose exec -T "$1" tierctl id 2>/dev/null \
    | sed -n 's/^user *\([0-9a-f]\{64\}\).*/\1/p' | head -n1 || true
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

# Both devices must report the same (shared) user id.
ua="$(user_id_of devicea)"; ub="$(user_id_of deviceb)"
if [ -z "$ua" ] || [ "$ua" != "$ub" ]; then
  echo "FAIL: devices do not share one user id (devicea=$ua deviceb=$ub)"
  exit 1
fi
sender_user="$(user_id_of sender)"
echo "shared user id = $ua"
echo "sender user id = $sender_user"

# Let presence + user enrollment settle on the communicators.
sleep "$settle_seconds"

failures=0
stamp="$(date +%s)"
suites="classical hybrid pq"
marker_for() { printf 'multi-%s-%s' "$1" "$stamp"; }

for suite in $suites; do
  if compose exec -T sender tierctl send-user "$ua" "$suite" "$(marker_for "$suite")"; then
    echo "sender sent $suite to the user"
  else
    echo "FAIL: sender could not accept the $suite send-user"
    failures=$((failures + 1))
  fi
done

# Accumulate each device's inbox until all three markers show up or we time out.
collect() {  # $1 = service
  local acc="" got deadline
  deadline=$(( $(date +%s) + message_timeout ))
  while :; do
    got="$(compose exec -T "$1" tierctl inbox 2>/dev/null || true)"
    acc="$acc
$got"
    local have_all=1
    for suite in $suites; do
      printf '%s\n' "$acc" | grep -q "$(marker_for "$suite")" || have_all=0
    done
    [ "$have_all" = 1 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 1
  done
  printf '%s' "$acc"
}

for dev in devicea deviceb; do
  echo "---- $dev inbox ----"
  acc="$(collect "$dev")"
  printf '%s\n' "$acc" | grep -E '^from ' || true
  for suite in $suites; do
    if printf '%s\n' "$acc" | grep -q "suite=$suite.*$(marker_for "$suite")"; then
      echo "$dev received $suite"
    else
      echo "FAIL: $dev did not receive an intact $suite message"
      failures=$((failures + 1))
    fi
  done
  # Each delivered message must show the sender's user id.
  if printf '%s\n' "$acc" | grep -q "user ${sender_user:0:16}"; then
    echo "$dev saw the sender's user id"
  else
    echo "FAIL: $dev did not attribute the message to the sender's user"
    failures=$((failures + 1))
  fi
done

echo
if [ "$failures" -eq 0 ]; then
  echo "multi-identity e2e OK: a user on two devices both received, attributed to the sender's user"
  exit 0
fi
echo "multi-identity e2e FAILED: $failures check(s) failed"
exit 1
