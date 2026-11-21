# Installing tierd

This is the install path for **client nodes**, straight from the release `.deb`
attached to each tier-core GitHub Release. The scripts below download that
`.deb`, install it, apply a config preset, and handle updates.

## Requirements

- Ubuntu 22.04 or 24.04 (the package floor is `libc6 >= 2.34`).
- `amd64` - the architecture current releases ship.
- `curl` and `sudo`.
- IPv4 reachability to GitHub, **or** a proxy (see [IPv6-only networks](#ipv6-only-networks)):
  GitHub's API and release assets have no IPv6.

## Install

The install script downloads the release `.deb`, installs it with apt (so
dependencies resolve), and copies the chosen node config preset to
`/etc/tier/tierd.toml` on first install only - it never overwrites an existing
config. Re-running is safe: an already-installed version is skipped.

**Client node (default):**

```bash
curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash
```

**Validator node:**

```bash
curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash -s -- --preset=validator
```

**Pin an exact version** (default is the latest release):

```bash
curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh | sudo bash -s -- --version=v0.7.2
```

After installation the service is **enabled for boot but not started**, so you
can review the config first:

```bash
sudoedit /etc/tier/tierd.toml      # roles, network, seeds
sudo systemctl start tierd
```

The node stores its Ed25519 identity under `/var/lib/tier` and joins through the
preconfigured seeds, so no seed argument is required.

### Manual install (without the script)

Download the `.deb` from the [latest release](https://github.com/tier-org/tier-core/releases/latest)
(asset `tierd_<version>_amd64.deb`), then:

```bash
sudo apt install ./tierd_X.Y.Z_amd64.deb      # resolves dependencies
sudo cp /usr/share/doc/tierd/tierd.client.toml /etc/tier/tierd.toml   # or tierd.validator.toml
sudoedit /etc/tier/tierd.toml
sudo systemctl start tierd
```

Use `apt install ./file.deb`, not `dpkg -i`, so dependencies are pulled in.

## Updating

The update script installs the latest release only if it is newer than what you
have, preserving your `/etc/tier/tierd.toml` (it is a dpkg conffile). The
package does not restart tierd on upgrade, so the script restarts it itself -
**only if it was already running**, leaving a deliberately stopped node stopped.

```bash
curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/update.sh | sudo bash
```

### Manual update

```bash
sudo apt install ./tierd_X.Y.Z_amd64.deb   # newer version; keeps your config
sudo systemctl restart tierd               # pick up the new binary if running
```

The explicit `restart` is required: the release package's `postinst` enables but
does not restart the service, so a running node keeps the old binary until you
restart it.

## IPv6-only networks

GitHub serves its API and release assets over IPv4 only - `api.github.com`,
`github.com` and the asset host (`objects`/`release-assets.githubusercontent.com`)
have no AAAA record. So on a pure IPv6 network the install and update scripts
cannot reach the `.deb` directly. Route them through a dual-stack proxy:

```bash
curl -fsSL https://raw.githubusercontent.com/tier-org/tier-core/main/scripts/install.sh \
  | sudo bash -s -- --proxy=http://PROXY_HOST:3128
```

`--proxy` accepts `http://`, `https://` and `socks5h://` (use the `socks5h`
form so the proxy also resolves DNS). A CONNECT or SOCKS proxy **tunnels** the
TLS unchanged to GitHub, so integrity is preserved - the proxy only has to be
reachable over IPv6 and able to egress over IPv4; it never sees the plaintext.
`update.sh` takes the same `--proxy` flag.

curl also honours the `https_proxy` / `ALL_PROXY` environment variables, but
`curl | sudo bash` drops the environment, so either pass `--proxy` or run with
`sudo -E`. (The script itself is fetched from `raw.githubusercontent.com`, which
*does* have IPv6, so only the in-script GitHub calls need the proxy.)

Avoid reverse-proxy mirrors that re-terminate TLS and re-serve the `.deb`: the
release assets are not separately signed, so TLS-to-GitHub is the only integrity
guarantee, and a terminating mirror replaces that with trust in the mirror.

## Uninstall

Remove the package (keeps `/etc/tier`):

```bash
sudo apt remove tierd
```

Remove and purge all configuration:

```bash
sudo apt purge tierd
sudo rm -rf /etc/tier
```

## Config presets

The package ships ready-made presets in `/usr/share/doc/tierd/`:

- `tierd.client.toml` - edge node, dial-out only (the default).
- `tierd.validator.toml` - validator role.

They are reference files (overwritten on upgrade); the active config is the
single file `/etc/tier/tierd.toml`, which upgrades never touch. Copy the preset
you need into place, or edit the active config directly.
