#!/usr/bin/env bash
#
# Cut a release: bump the VERSION file, commit it, and tag the commit v<version>
# so the two can never drift. The release workflow fires on a pushed v* tag, so
# pushing is gated behind --push; without it the script stops after the local
# commit + tag and prints the exact push command.
#
# Usage:
#   scripts/release.sh <X.Y.Z | patch | minor | major> [--push]
#
# All validation runs before anything is written, so an aborted run leaves the
# working tree and git state untouched.

set -euo pipefail

die() {
  echo "release: $*" >&2
  exit 1
}

# --- parse arguments -------------------------------------------------------
[ $# -ge 1 ] || die "usage: scripts/release.sh <X.Y.Z | patch | minor | major> [--push]"

spec=$1
shift
push=0
for arg in "$@"; do
  case "$arg" in
    --push) push=1 ;;
    *) die "unknown argument: $arg" ;;
  esac
done

semver_re='^[0-9]+\.[0-9]+\.[0-9]+$'

# --- locate the repo and read the current version --------------------------
root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$root"

[ -f VERSION ] || die "no VERSION file at repo root"
current=$(head -n1 VERSION | tr -d '[:space:]')
[[ $current =~ $semver_re ]] || die "current VERSION is not semver: '$current'"

# --- resolve the new version (explicit, or a bump of the current one) ------
IFS='.' read -r cur_major cur_minor cur_patch <<<"$current"
case "$spec" in
  major) new="$((cur_major + 1)).0.0" ;;
  minor) new="${cur_major}.$((cur_minor + 1)).0" ;;
  patch) new="${cur_major}.${cur_minor}.$((cur_patch + 1))" ;;
  *)     new=$spec ;;
esac
[[ $new =~ $semver_re ]] || die "target version is not semver: '$new'"

tag="v$new"

# --- return 0 if $1 is strictly greater than $2 (semver order) -------------
ver_gt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]
}

ver_gt "$new" "$current" || die "new version $new is not greater than current $current"

# --- branch, cleanliness, and remote-sync guards ---------------------------
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "must be on 'main' (currently on '$branch')"

git diff --quiet || die "working tree has unstaged changes; the release commit must contain only the bump"
git diff --cached --quiet || die "index has staged changes; the release commit must contain only the bump"

echo "release: fetching origin..." >&2
git fetch --quiet origin main
local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse origin/main)
[ "$local_head" = "$remote_head" ] || die "local main is not in sync with origin/main (pull/push first)"

# --- new version must beat the latest existing tag -------------------------
latest_tag=$(git tag --list 'v[0-9]*' | sort -V | tail -n1)
if [ -n "$latest_tag" ]; then
  latest_ver=${latest_tag#v}
  ver_gt "$new" "$latest_ver" || die "new version $new is not greater than latest tag $latest_tag"
fi

# --- the tag must not already exist, locally or on origin ------------------
git rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1 && die "tag $tag already exists locally"
[ -z "$(git ls-remote --tags origin "refs/tags/$tag")" ] || die "tag $tag already exists on origin"

# --- all checks passed: write, commit, tag ---------------------------------
printf '%s\n' "$new" >VERSION
git add VERSION
git commit --quiet -m "$new"
git tag -a "$tag" -m "$new"

echo "release: committed VERSION=$new and tagged $tag (at $(git rev-parse --short HEAD))" >&2

if [ "$push" -eq 1 ]; then
  echo "release: pushing main..." >&2
  git push origin main
  echo "release: pushing tag $tag (this triggers the release build)..." >&2
  git push origin "$tag"
  echo "release: done. $tag is live; watch the release workflow." >&2
else
  echo "release: not pushed. To publish (this triggers the release build):" >&2
  echo "  git push origin main && git push origin $tag" >&2
fi
