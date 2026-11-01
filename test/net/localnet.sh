#!/usr/bin/env bash
# One-command local mesh for manual inspection. The network is internal (no
# internet) and uses TIER_SEEDS to replace the baked production seeds, so it is
# fully isolated from the real network.
#
#   localnet.sh up       build the image and start the 4-node mesh
#   localnet.sh status   run `tierctl peers` on every node
#   localnet.sh logs     follow the daemon logs
#   localnet.sh down     stop and remove the mesh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

project="tier-localnet"
nodes="node1 node2 node3 node4"
compose() { docker compose -p "$project" "$@"; }

case "${1:-up}" in
  up)
    "$here/build.sh"
    compose up -d
    echo
    echo "mesh up. inspect with:"
    echo "  $0 status"
    echo "  docker compose -p $project exec node1 tierctl peers"
    ;;
  status)
    for n in $nodes; do
      echo "== $n =="
      compose exec -T "$n" tierctl peers || true
      echo
    done
    ;;
  logs)
    compose logs -f
    ;;
  down)
    compose down -v --remove-orphans
    ;;
  *)
    echo "usage: $0 {up|status|logs|down}" >&2
    exit 2
    ;;
esac
