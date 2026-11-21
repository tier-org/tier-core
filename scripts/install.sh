#!/usr/bin/env bash
# Install tierd from a tier-core GitHub Release .deb.
#
# This is the direct-from-release path for clients who do not use the Geek
# Foundation PPA: it downloads the signed-over-TLS .deb attached to a release,
# installs it with apt (so dependencies resolve), and copies the chosen node
# config preset to /etc/tier/tierd.toml on first install. For managed, automatic
# updates use the PPA instead (see GeekFoundation/tier-ppa); here, updates are a
# manual step - run scripts/update.sh.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash -s -- --preset=validator
#   curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash -s -- --version=v0.7.2
#
# Options:
#   --preset=<name>   Node config preset: client (default) or validator.
#                     Copies /usr/share/doc/tierd/tierd.<name>.toml to
#                     /etc/tier/tierd.toml on first install only; never
#                     overwrites an existing config.
#   --version=vX.Y.Z  Install this exact release tag (default: latest release).
#   --repo=<owner/n>  Source repository (default: tier-org/tier-core).
#   --proxy=<url>     Route the GitHub requests through a proxy (http://,
#                     https:// or socks5h://). Needed on IPv6-only networks:
#                     GitHub's API and release assets are IPv4-only, so point
#                     this at a dual-stack CONNECT/SOCKS proxy and it tunnels
#                     the TLS straight through to GitHub (integrity preserved -
#                     the proxy never terminates the connection). curl also
#                     honours the https_proxy/ALL_PROXY env vars, but note that
#                     `curl | sudo bash` drops the environment, so pass the flag
#                     (or use `sudo -E`).
#
# Re-running is safe: if the requested version is already installed, the install
# step is skipped.

set -euo pipefail

REPO="tier-org/tier-core"
PACKAGE="tierd"
PRESET="client"
VERSION=""  # empty = latest release
PROXY=""    # empty = direct (or whatever curl reads from the environment)

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --preset=client|--preset=validator)
            PRESET="${arg#--preset=}"
            ;;
        --preset=*)
            echo "error: unknown preset '${arg#--preset=}'; valid values: client, validator" >&2
            exit 1
            ;;
        --version=*)
            VERSION="${arg#--version=}"
            ;;
        --repo=*)
            REPO="${arg#--repo=}"
            ;;
        --proxy=*)
            PROXY="${arg#--proxy=}"
            ;;
        *)
            echo "error: unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
step() { echo "==> $*"; }
skip() { echo "    (skip) $*"; }

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

# curl proxy args, empty unless --proxy was given (then: -x <url>).
CURL_PROXY=()

# Latest release tag via the GitHub API (no auth needed for a public repo).
latest_tag() {
    curl -fsSL "${CURL_PROXY[@]}" "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -n1 \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
need_root
require curl
require dpkg
require apt-get

ARCH="$(dpkg --print-architecture)"

if [ -n "$PROXY" ]; then
    CURL_PROXY=(-x "$PROXY")
    echo "    using proxy: $PROXY"
fi

# ---------------------------------------------------------------------------
# Step 1: resolve the release tag and the .deb asset name
# ---------------------------------------------------------------------------
if [ -z "$VERSION" ]; then
    step "Resolving the latest release of ${REPO}"
    VERSION="$(latest_tag)"
    if [ -z "$VERSION" ]; then
        echo "error: could not determine the latest release tag" >&2
        echo "       check network access or pass --version=vX.Y.Z" >&2
        exit 1
    fi
fi

# Tag is vX.Y.Z; the Debian package version and asset drop the leading 'v'.
PKGVER="${VERSION#v}"
DEB="${PACKAGE}_${PKGVER}_${ARCH}.deb"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${DEB}"

# ---------------------------------------------------------------------------
# Step 2: install the package (skip if the exact version is already present)
# ---------------------------------------------------------------------------
installed="$(dpkg-query -W -f='${Version}' "$PACKAGE" 2>/dev/null || true)"
if [ "$installed" = "$PKGVER" ]; then
    skip "$PACKAGE $PKGVER is already installed"
else
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    step "Downloading ${DEB} (${VERSION})"
    if ! curl -fSL "${CURL_PROXY[@]}" --proto '=https' --tlsv1.2 -o "${tmp}/${DEB}" "$URL"; then
        echo "error: download failed: $URL" >&2
        echo "       releases currently ship ${ARCH}; verify the tag and arch exist." >&2
        echo "       on an IPv6-only network GitHub is unreachable (its release" >&2
        echo "       assets are IPv4-only); route through a proxy with --proxy=<url>." >&2
        exit 1
    fi

    # mktemp -d is 0700/root, so apt's sandbox user (_apt) cannot read the local
    # file and apt falls back to an unsandboxed root fetch with a noisy warning.
    # Make the dir and file readable so the sandbox stays intact (the .deb is a
    # public release artifact anyway).
    chmod 0755 "$tmp"
    chmod 0644 "${tmp}/${DEB}"

    step "Installing ${DEB}"
    # apt-get on a local path resolves dependencies (plain dpkg -i would not).
    apt-get install -y "${tmp}/${DEB}"
fi

# ---------------------------------------------------------------------------
# Step 3: apply the config preset on first install only
# ---------------------------------------------------------------------------
CONFIG_DST="/etc/tier/tierd.toml"
CONFIG_SRC="/usr/share/doc/${PACKAGE}/tierd.${PRESET}.toml"

step "Applying preset '${PRESET}'"
if [ -f "$CONFIG_DST" ]; then
    skip "$CONFIG_DST already exists - not overwritten"
elif [ ! -f "$CONFIG_SRC" ]; then
    echo "error: preset file not found: $CONFIG_SRC" >&2
    echo "       the installed package version may not ship this preset" >&2
    exit 1
else
    mkdir -p "$(dirname "$CONFIG_DST")"
    cp "$CONFIG_SRC" "$CONFIG_DST"
    echo "    wrote $CONFIG_DST (from preset '${PRESET}')"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo
echo "tierd $(dpkg-query -W -f='${Version}' "$PACKAGE") is installed."
echo "Preset: ${PRESET}"
echo
echo "The service is enabled for boot but not started. Review the config, then start:"
echo "  sudoedit ${CONFIG_DST}"
echo "  sudo systemctl start tierd"
echo
echo "Update later with:"
echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/update.sh | sudo bash"
