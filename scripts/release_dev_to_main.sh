#!/usr/bin/env bash
#
# Merge dev into main and cut a patch release in one step. Run this from the
# main-branch checkout (the directory that tracks 'main'); it never touches dev.
#
# Steps:
#   1. fetch origin (refresh origin/main and origin/dev)
#   2. fast-forward local main to origin/main (fails loudly if they diverged)
#   3. merge origin/dev into main (message: -m, else the single dev commit's
#      title, else git's default)
#   4. push main
#   5. scripts/release.sh patch --push  (bump VERSION, commit, tag v*, push both)
#
# The tag push triggers the release build. scripts/release.sh carries its own
# guards (clean tree, local main == origin/main, new version beats the latest
# tag), and this script requires local main to already be in sync, so an aborted
# run leaves git state recoverable by hand.
#
# Usage:
#   scripts/release_dev_to_main.sh                       # patch bump (default)
#   scripts/release_dev_to_main.sh minor                 # major / X.Y.Z
#   scripts/release_dev_to_main.sh minor -m "text"       # custom merge message

set -euo pipefail

die() {
  echo "release-dev-to-main: $*" >&2
  exit 1
}

# The version bump to pass through to scripts/release.sh (patch by default).
# -m/--message is parsed separately and may appear before or after the version.
spec="patch"
merge_message=""
positional=0
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
    -*)
      die "unknown option: $1"
      ;;
    *)
      [ "$positional" -eq 0 ] || die "unexpected argument: $1"
      spec=$1
      positional=1
      shift
      ;;
  esac
done

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$root"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "must be on 'main' (currently on '$branch')"

echo "release-dev-to-main: fetching origin..." >&2
git fetch origin

# Keep local main current with the remote before merging. --ff-only turns a
# surprise divergence into an error instead of a silent merge commit.
git merge --ff-only origin/main

# Bring dev's work into main. An explicit -m wins; otherwise use the single
# incoming commit's title. See merge_dev_to_main.sh for the rationale. With a
# fast-forward there is no merge commit, so the message is unused.
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

echo "release-dev-to-main: pushing main..." >&2
git push origin main

# Bump + commit VERSION, tag it, and push main + tag (which fires the release).
exec "$root/scripts/release.sh" "$spec" --push
