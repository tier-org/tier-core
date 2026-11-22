#!/usr/bin/env bash
# tier-agent e2e gate. Brings up two communicators + two edge clients (IPv4-only
# internal mesh), runs tier-agent as a COLLECTOR on clientb and as an AGENT on
# clienta, and asserts that a gauge AND an event shipped by the agent arrive in
# the collector's store - read back through the collector's local query socket.
#
# The two clients share no direct connection and never gossip each other, so a
# delivered sample proves the full relayed telemetry path: the collector user
# registers presence on a communicator, the agent resolves it by lookup and its
# sealed telemetry is relayed through a responsible communicator. The agent runs
# in exec mode (re-ships every interval), so a dropped cold-start first message
# (best-effort online-only delivery) is retried rather than lost.
#
# Env:
#   CONVERGE_TIMEOUT        seconds to wait for the clients to attach (default 40)
#   DELIVER_TIMEOUT         seconds to wait for delivery (default 60)
#   TIERD_BIN / TIERCTL_BIN / TIER_AGENT_BIN
#                           reuse prebuilt binaries instead of a clean-room build
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
root="$(cd "$here/../.." && pwd)"

project="tier-agent-e2e"
compose_file="docker-compose.agent.yml"
image="tier-agent-localnet:latest"
build_image="tier-localnet-build"
converge_timeout="${CONVERGE_TIMEOUT:-40}"
deliver_timeout="${DELIVER_TIMEOUT:-60}"

compose() { docker compose -p "$project" -f "$compose_file" "$@"; }
cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

# --- stage binaries (tierd, tierctl, tier-agent) ---
mkdir -p bin
if [ -n "${TIERD_BIN:-}" ] && [ -n "${TIERCTL_BIN:-}" ] && \
   [ -n "${TIER_AGENT_BIN:-}" ]; then
  echo "== staging prebuilt binaries =="
  cp "$TIERD_BIN" bin/tierd
  cp "$TIERCTL_BIN" bin/tierctl
  cp "$TIER_AGENT_BIN" bin/tier-agent
else
  echo "== staging binaries from clean-room build image ($build_image) =="
  if ! docker image inspect "$build_image" >/dev/null 2>&1; then
    echo "   building $build_image (one-time clean-room compile) ..."
    docker build -f "$root/packaging/Dockerfile.build" -t "$build_image" "$root"
  fi
  cid="$(docker create "$build_image")"
  docker cp "$cid:/src/build/apps/node/tierd" bin/tierd
  docker cp "$cid:/src/build/apps/cli/tierctl" bin/tierctl
  docker cp "$cid:/src/build/apps/agent/tier-agent" bin/tier-agent
  docker rm "$cid" >/dev/null
fi

echo "== building image $image =="
docker build -t "$image" -f Dockerfile.agent .

echo "== bringing up 2 communicators + 2 clients (IPv4-only) =="
compose up -d

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

sleep 3  # let presence registration reach the responsible communicator

stamp="$(date +%s)"

# --- collector on clientb ---
echo "== starting collector on clientb =="
compose exec -T clientb sh -c 'cat > /var/lib/tier/collector.toml' <<'EOF'
role = "collector"
admin_socket = "/run/tierd/tierd.sock"
seed_file = "/var/lib/tier/agent-collector.seed"
[collector]
store = "/var/lib/tier/agent-store.log"
query_socket = "/run/tierd/agent-query.sock"
EOF
compose exec -T -d clientb sh -c \
  'tier-agent --config /var/lib/tier/collector.toml >/var/lib/tier/collector.log 2>&1'

# Collector's tier address, from its startup line.
caddr=""
for _ in $(seq 1 30); do
  caddr="$(compose exec -T clientb sed -n 's/.*address: *//p' \
    /var/lib/tier/collector.log 2>/dev/null | head -n1 | tr -d '\r')"
  [ -n "$caddr" ] && break
  sleep 0.5
done
if [ -z "$caddr" ]; then
  echo "FAIL: collector did not report its address"
  compose exec -T clientb cat /var/lib/tier/collector.log 2>/dev/null || true
  exit 1
fi
echo "collector address: $caddr"

# --- agent on clienta (exec mode: re-ships every interval) ---
echo "== starting agent on clienta =="
compose exec -T clienta sh -c 'cat > /var/lib/tier/emit.sh' <<EOF
#!/bin/sh
echo "gauge e2e.metric $stamp"
echo "event e2e.boot started-$stamp"
EOF
compose exec -T clienta sh -c 'chmod +x /var/lib/tier/emit.sh'
compose exec -T clienta sh -c 'cat > /var/lib/tier/agent.toml' <<EOF
role = "agent"
admin_socket = "/run/tierd/tierd.sock"
seed_file = "/var/lib/tier/agent-agent.seed"
[agent]
collector = "$caddr"
interval = 2
exec = "/var/lib/tier/emit.sh"
EOF
compose exec -T -d clienta sh -c \
  'tier-agent --config /var/lib/tier/agent.toml >/var/lib/tier/agent.log 2>&1'

# --- poll the collector store through its query socket ---
echo "== waiting up to ${deliver_timeout}s for telemetry to arrive =="
deadline=$(( $(date +%s) + deliver_timeout ))
got_gauge=0; got_event=0
while :; do
  snap="$(compose exec -T clientb tier-agent query \
    /run/tierd/agent-query.sock e2e 2>/dev/null || true)"
  printf '%s\n' "$snap" | grep -q "e2e.metric $stamp" && got_gauge=1
  printf '%s\n' "$snap" | grep -q "e2e.boot started-$stamp" && got_event=1
  [ "$got_gauge" = 1 ] && [ "$got_event" = 1 ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 2
done

echo "---- collector snapshot (filter: e2e) ----"
compose exec -T clientb tier-agent query /run/tierd/agent-query.sock e2e \
  2>/dev/null || true

failures=0
if [ "$got_gauge" = 1 ]; then echo "gauge delivered"; else
  echo "FAIL: gauge not delivered"; failures=$((failures + 1)); fi
if [ "$got_event" = 1 ]; then echo "event delivered"; else
  echo "FAIL: event not delivered"; failures=$((failures + 1)); fi

if [ "$failures" -ne 0 ]; then
  echo "---- agent.log ----";     compose exec -T clienta cat /var/lib/tier/agent.log 2>/dev/null || true
  echo "---- collector.log ----"; compose exec -T clientb cat /var/lib/tier/collector.log 2>/dev/null || true
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "agent e2e OK: telemetry crossed edge -> communicator -> edge (gauge + event)"
  exit 0
fi
echo "agent e2e FAILED: $failures check(s) failed"
exit 1
