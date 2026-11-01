# Local mesh harness (Docker)

A four-node, dual-stack tier mesh on an **internal** Docker network. Two uses:

- **localnet** - bring the mesh up and poke it by hand.
- **e2e** - bring it up, assert every node discovered the whole mesh and
  advertises both IPv4 and IPv6, then tear it down. Run it before a release.

The mesh is doubly isolated from production. The Docker network is
`internal: true`, so the containers have no route off the bridge, and each node
runs with `TIER_SEEDS` pointing at the other containers, which **fully replaces**
the baked production seeds. On top of that the image sets `TIER_NETWORK=localnet`
(a private cluster), so even a stray address overlap could not complete a
handshake with a mainnet node. No internet, no production contamination. (See
`TIER_NETWORK` and `TIER_SEEDS` in the top-level README.)

## Requirements

Docker with IPv6 enabled on the daemon. One-time setup in
`/etc/docker/daemon.json`:

```json
{ "experimental": true, "ipv6": true, "fixed-cidr-v6": "fd00:d0cc::/64", "ip6tables": true }
```

then `sudo systemctl restart docker`. (`ip6tables` is an experimental daemon
feature before Docker 27, so `experimental` must be set too or the daemon will
not start; it is harmless to leave on with newer Docker. The release workflow
configures this automatically for CI.)

## Use

    make localnet-up        # build image + start the mesh
    make localnet-status    # tierctl peers on every node
    make localnet-down      # stop and remove

    make e2e                # build, converge, assert, tear down (release gate)

Or call the scripts directly in `test/net/` (`./localnet.sh up`, `./e2e.sh`).

By default the binaries are built as a static Release into `build-localnet/`.
To reuse binaries built elsewhere, set `TIERD_BIN` and `TIERCTL_BIN`:

    TIERD_BIN=build/apps/node/tierd TIERCTL_BIN=build/apps/cli/tierctl ./e2e.sh

## Knobs (e2e)

- `DISCOVERY_TIMEOUT` - seconds to wait for convergence (default 30).
- `REQUIRE_DUALSTACK` - `1` (default) also asserts IPv4+IPv6 per node; `0`
  checks discovery only.
