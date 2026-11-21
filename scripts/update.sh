#!/usr/bin/env bash
# Update an installed tierd to the latest tier-core GitHub Release .deb.
#
# This is the manual-update counterpart to scripts/install.sh for clients who
# install straight from releases rather than through the Geek Foundation PPA
# (which updates via apt / unattended-upgrades). It compares the installed
# version against the latest release and, only if the release is newer, installs
# it. The package's postinst enables but does not restart tierd on upgrade, so
# this script restarts the service itself - but only if it was already running,
# matching the "a node the operator stopped stays stopped" behaviour.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/update.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/update.sh | sudo bash -s -- --repo=tier-org/tier-core
#
# Options:
#   --repo=<owner/n>  Source repository (default: tier-org/tier-core).
#   --proxy=<url>     Route the GitHub requests through a proxy (http://,
#                     https:// or socks5h://). Needed on IPv6-only networks:
#                     GitHub's API and release assets are IPv4-only, so a dual-
#                     stack CONNECT/SOCKS proxy tunnels the TLS through to them.

set -euo pipefail

REPO="tier-org/tier-core"
PACKAGE="tierd"
PROXY=""

for arg in "$@"; do
    case "$arg" in
        --repo=*) REPO="${arg#--repo=}" ;;
        --proxy=*) PROXY="${arg#--proxy=}" ;;
        *) echo "error: unknown argument: $arg" >&2; exit 1 ;;
    esac
done

step() { echo "==> $*"; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: run as root or with sudo" >&2
        exit 1
    fi
}

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: '$1' is required but not installed" >&2
        exit 1
    }
}

CURL_PROXY=()

latest_tag() {
    curl -fsSL "${CURL_PROXY[@]}" "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -n1 \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

need_root
require curl
require dpkg
require apt-get

ARCH="$(dpkg --print-architecture)"

if [ -n "$PROXY" ]; then
    CURL_PROXY=(-x "$PROXY")
    echo "    using proxy: $PROXY"
fi

installed="$(dpkg-query -W -f='${Version}' "$PACKAGE" 2>/dev/null || true)"
if [ -z "$installed" ]; then
    echo "error: $PACKAGE is not installed; run scripts/install.sh first" >&2
    exit 1
fi

step "Resolving the latest release of ${REPO}"
TAG="$(latest_tag)"
if [ -z "$TAG" ]; then
    echo "error: could not determine the latest release tag" >&2
    exit 1
fi
PKGVER="${TAG#v}"

echo "    installed: ${installed}"
echo "    latest:    ${PKGVER} (${TAG})"

# Only move forward: skip if already current or somehow ahead of the release.
if ! dpkg --compare-versions "$installed" lt "$PKGVER"; then
    echo "tierd is already up to date (${installed}); nothing to do."
    exit 0
fi

# Remember whether the node was running, so we restart it (and only it) after.
was_active=false
if systemctl is-active --quiet tierd; then
    was_active=true
fi

DEB="${PACKAGE}_${PKGVER}_${ARCH}.deb"
URL="https://github.com/${REPO}/releases/download/${TAG}/${DEB}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

step "Downloading ${DEB}"
if ! curl -fSL "${CURL_PROXY[@]}" --proto '=https' --tlsv1.2 -o "${tmp}/${DEB}" "$URL"; then
    echo "error: download failed: $URL" >&2
    echo "       on an IPv6-only network GitHub is unreachable (release assets" >&2
    echo "       are IPv4-only); route through a proxy with --proxy=<url>." >&2
    exit 1
fi

step "Upgrading ${installed} -> ${PKGVER}"
# mktemp -d is 0700/root, so apt's sandbox user (_apt) cannot read the local
# file and apt falls back to an unsandboxed root fetch with a noisy warning.
# Make the dir and file readable so the sandbox stays intact (the .deb is a
# public release artifact anyway).
chmod 0755 "$tmp"
chmod 0644 "${tmp}/${DEB}"
# Conffiles (/etc/tier/tierd.toml, tierd.env) are preserved by dpkg on upgrade.
apt-get install -y "${tmp}/${DEB}"

if [ "$was_active" = true ]; then
    step "Restarting tierd (it was running)"
    systemctl restart tierd
else
    echo "    tierd was not running; left stopped. Start with: systemctl start tierd"
fi

echo
echo "tierd updated to $(dpkg-query -W -f='${Version}' "$PACKAGE")."
