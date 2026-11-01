#!/usr/bin/env bash
# Stage the tierd + tierctl binaries into test/net/bin and build the localnet
# runtime image (tier-localnet:latest).
#
# The runtime image is Ubuntu 22.04, matching the released .deb, so the binaries
# must share that glibc floor (2.35). By default they are built in the clean-room
# image (packaging/Dockerfile.build), exactly as the release is - a host build on
# a newer distro would link a newer glibc and fail to start in the container.
#
# Set TIERD_BIN and TIERCTL_BIN to reuse binaries already built on a 22.04 host
# (e.g. the release workflow's build/ on the ubuntu-22.04 runner); the clean-room
# build is then skipped.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

: "${TIERD_BIN:=}"
: "${TIERCTL_BIN:=}"

mkdir -p "$here/bin"

if [ -n "$TIERD_BIN" ] && [ -n "$TIERCTL_BIN" ]; then
  echo "== staging prebuilt binaries =="
  cp "$TIERD_BIN" "$here/bin/tierd"
  cp "$TIERCTL_BIN" "$here/bin/tierctl"
else
  echo "== clean-room build (Ubuntu 22.04 glibc floor) =="
  docker build -f "$root/packaging/Dockerfile.build" -t tier-localnet-build "$root"
  cid="$(docker create tier-localnet-build)"
  trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:/src/build/apps/node/tierd" "$here/bin/tierd"
  docker cp "$cid:/src/build/apps/cli/tierctl" "$here/bin/tierctl"
fi

echo "== building image tier-localnet:latest =="
docker build -t tier-localnet:latest -f "$here/Dockerfile" "$here"

# Rebuilding the images above moves the tags onto fresh images and leaves the
# previous layers dangling. Prune only ours (matched by the LABEL baked into
# both Dockerfiles), so repeated runs do not accumulate <none> images and no
# unrelated dangling images on the host are touched.
echo "== pruning this harness's dangling images =="
docker image prune -f --filter label=tier.harness=localnet >/dev/null 2>&1 || true
