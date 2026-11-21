#!/usr/bin/env bash
#
# Merge dev into main and push - without cutting a release. Run this from the
# main-branch checkout (the directory that tracks 'main'); it never touches dev.
# Use scripts/release_dev_to_main.sh instead when you also want to bump VERSION
# and tag a release.
#
# Steps:
#   1. fetch origin (refresh origin/main and origin/dev)
#   2. fast-forward local main to origin/main (fails loudly if they diverged)
#   3. merge origin/dev into main
#   4. push main
#
# No VERSION bump and no tag, so the release workflow is not triggered. Because
# this requires local main to already be in sync before merging, an aborted run
# leaves git state recoverable by hand.
#
# Usage:
#   scripts/merge_dev_to_main.sh

set -euo pipefail

die() {
  echo "merge-dev-to-main: $*" >&2
  exit 1
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$root"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "must be on 'main' (currently on '$branch')"

echo "merge-dev-to-main: fetching origin..." >&2
git fetch origin

# Keep local main current with the remote before merging. --ff-only turns a
# surprise divergence into an error instead of a silent merge commit.
git merge --ff-only origin/main

# Bring dev's work into main.
git merge --no-edit origin/dev

echo "merge-dev-to-main: pushing main..." >&2
git push origin main

echo "merge-dev-to-main: done (no tag; release workflow not triggered)." >&2
