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
#   3. merge origin/dev into main (message: -m, else the single dev commit's
#      title, else git's default)
#   4. push main
#
# No VERSION bump and no tag, so the release workflow is not triggered. Because
# this requires local main to already be in sync before merging, an aborted run
# leaves git state recoverable by hand.
#
# Usage:
#   scripts/merge_dev_to_main.sh [-m|--message "text"]
#   scripts/merge_dev_to_main.sh -m "feature batch for 0.7.13"

set -euo pipefail

die() {
  echo "merge-dev-to-main: $*" >&2
  exit 1
}

# Optional merge message. Without it, the single incoming dev commit's title
# is used; with several incoming commits git's default message is kept.
merge_message=""
while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message)
      [ $# -ge 2 ] || die "$1 requires a message"
      [ -n "$2" ] || die "$1 requires a non-empty message"
      merge_message=$2
      shift 2
      ;;
    -m=*|--message=*)
      merge_message=${1#*=}
      [ -n "$merge_message" ] || die "--message requires a non-empty message"
      shift
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$root"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "must be on 'main' (currently on '$branch')"

echo "merge-dev-to-main: fetching origin..." >&2
git fetch origin

# Keep local main current with the remote before merging. --ff-only turns a
# surprise divergence into an error instead of a silent merge commit.
git merge --ff-only origin/main

# Bring dev's work into main. An explicit -m wins. Otherwise: a merge commit is
# a new commit with two parents, so git cannot inherit the dev commit's title —
# --no-edit only suppresses the editor and leaves git's generated "Merge
# remote-tracking branch ..." text. Supply the title explicitly when dev brings
# exactly one commit; leave git's default for a real multi-commit merge. A
# fast-forward creates no merge commit, so any message is unused there.
if [ -n "$merge_message" ]; then
  git merge -m "$merge_message" origin/dev
else
  new_commits=$(git rev-list --count HEAD..origin/dev)
  subject=$(git log -1 --format=%s origin/dev)
  if [ "$new_commits" -eq 1 ] && [ -n "$subject" ]; then
    git merge -m "$subject" origin/dev
  else
    git merge --no-edit origin/dev
  fi
fi

echo "merge-dev-to-main: pushing main..." >&2
git push origin main

echo "merge-dev-to-main: done (no tag; release workflow not triggered)." >&2
