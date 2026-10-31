# tier-core

Core node for Tier, a decentralized network for encrypted messaging and payments.

**Status:** early scaffold. The QUIC transport (ngtcp2 + wolfSSL) with mutual
TLS 1.3 authentication and certificate-bound node identity handshakes, and the
gossip/membership layer (SWIM) runs on top of it. NAT traversal (hole punching)
and the relay node role are not implemented yet.

## Layout

- `libs/core` - transport-agnostic core (sans-I/O state machines)
- `libs/crypto` - cryptographic seam (signing / KEX / hash), backed by wolfSSL
- `libs/net` - QUIC networking (ngtcp2 + wolfSSL)
- `apps/node` - node daemon
- `apps/cli` - command-line client
- `tests` - unit tests (CTest)
- `fuzz` - libFuzzer targets for untrusted-input decoders (Clang only)

## Cryptography

Node identity and signatures use **Ed25519** by default. It is the only scheme
the project currently supports, tests, and makes any guarantees about. Ed25519
is a deliberate choice over secp256k1: deterministic and constant-time by
construction (no per-signature nonce to leak a key), natively supported by the
TLS 1.3 / X.509 stack the certificate-bound identity relies on, and fast to
batch-verify. Blockchain-ecosystem compatibility, secp256k1's main draw, is a
non-goal here.

Post-quantum algorithms are **experimental and unsupported**. ML-DSA
(signatures) and a hybrid ML-KEM key exchange are planned behind the same
algorithm-agnostic interfaces, but they are **not** enabled by default and
**no guarantees whatsoever** are made about them - on-wire formats,
interoperability, and security properties may change or break at any time.

The design goal is crypto-agility: every key, signature, and certificate is
meant to carry an explicit algorithm identifier; a verifier supports a *set* of
algorithms rather than one; and any network-wide change of the algorithm that
peers *produce* is a coordinated activation, never a simultaneous flag day.
Peers may therefore run different algorithms as long as each side can verify
what the other presents. Ed25519 (classical) is quantum-vulnerable; this is
accepted for v0 and addressed by the planned migration path, not by the current
default.

## Dependencies

Build-time:

- a C++20 compiler (GCC >= 11 or Clang >= 14)
- CMake >= 3.25 and a generator (Ninja or Make). Ubuntu 24.04 ships a new
  enough CMake; Ubuntu 22.04 ships 3.22, so install a newer one there (pip,
  snap, or Kitware's apt repo).
- Git, for the vendored submodules
- for packaging a `.deb`: `dpkg-dev` and `file`

On Debian/Ubuntu: `apt-get install build-essential cmake git ninja-build`.

wolfSSL and ngtcp2 are vendored as git submodules under `vendor/` and built
from source, so clone with submodules:

    git clone --recurse-submodules <url>
    # or, in an existing checkout:
    git submodule update --init --recursive

Runtime: only `libc6`. wolfSSL, ngtcp2, libstdc++ and libgcc are linked
statically into the binary.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    cmake --build build -j
    ctest --test-dir build --output-on-failure

AddressSanitizer and UndefinedBehaviorSanitizer are on by default
(`-DTIER_SANITIZE=OFF` to disable). Warnings are errors by default
(`-DTIER_WERROR=OFF` to relax). Fuzz targets build with `-DTIER_FUZZ=ON` under Clang.

### Release (static) binary

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTIER_SANITIZE=OFF \
      -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++"
    cmake --build build -j

`build/apps/node/tier-node` then links only against glibc (`ldd` shows just
`libc`/`libm`). glibc stays dynamic on purpose - a fully static glibc binary
breaks NSS name resolution.

## Packaging and releases

The release `.deb` (binary + hardened systemd unit + default config) is built
with CPack. Build it in the clean-room Docker image so the glibc floor and file
permissions are deterministic:

    docker build -f packaging/Dockerfile.build -t tier-build .
    docker run --rm -v "$PWD/out:/out" tier-build sh -c 'cp /src/build/*.deb /out/'

The image is Ubuntu 22.04, so the package depends on `libc6 (>= 2.34)` and runs
on Ubuntu 22.04 and 24.04. A local `cd build && cpack -G DEB` also works, but a
restrictive umask leaks into the packaged directory permissions, so prefer the
Docker (or CI) path for artifacts you distribute.

Pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds
the package and attaches the `.deb` to a GitHub Release. To install and run:

    sudo dpkg -i tier-node_X.Y.Z_amd64.deb
    sudoedit /etc/tier/tier-node.env      # set TIER_ARGS: listen port, optional seed
    sudo systemctl start tier-node

The node stores its Ed25519 identity under `/var/lib/tier` (systemd
StateDirectory). It joins through the preconfigured seeds below, so no seed
argument is required; an explicit `<seed_ip> <seed_port>` in `TIER_ARGS` is
dialed in addition.

## Network seeds

The bootstrap seeds are compiled into the binary - `libs/core/include/tier/core/seeds.hpp`
is the single source of truth. There is no runtime fetch (no DNS seed list, no
HTTPS), so joining the network adds no extra point of failure; the seed set
changes only by editing that file and cutting a new release.

A fresh node dials every seed at startup over whichever family it has (IPv6
preferred). Reaching one seed is enough - the rest of the membership arrives by
anti-entropy. Each seed is listed with both an IPv4 and an IPv6 address on UDP
port 7777; a node that is itself a seed skips its own address, and a connection
to self is dropped regardless. Seed identities are not pinned: a peer's identity
is authenticated by the TLS handshake, so a wrong address fails closed rather
than impersonating a seed (key pinning is a possible later hardening).

## Node requirements

The lite node is what this repo builds today; its figures are grounded in the
current binary. The **validator role is not implemented yet**, so its figures
are architectural estimates from the design, meant for provisioning with
headroom and to be revised once the role exists and is measured. When sizing a
server, use the "comfortable" column.

Common baseline for every role:

- Linux x86-64 (amd64), packaged for Ubuntu 22.04 / 24.04, glibc >= 2.34.
- Static binary: no runtime dependency beyond `libc6`.
- IPv4 and/or IPv6 - the daemon binds dual-stack (`::`).
- One reachable UDP port (the listen port in `TIER_ARGS`).

### Lite node (client / general participant)

Runs the messaging and wallet side: holds its own coins and chat locally, joins
the peer mesh, and contacts validators to spend. Light and intermittent-friendly,
and works behind NAT (direct connections plus hole punching).

| Resource | Minimum | Comfortable |
|----------|---------|-------------|
| CPU      | 1 core  | 2 cores |
| RAM      | 256 MB  | 512 MB - 1 GB |
| Disk     | 1 GB plus your own wallet/chat data | SSD, a few GB |
| Network  | ~1 Mbit/s, NAT is fine, no public IP needed | stable link |
| Uptime   | none, may be offline | - |

The base-layer footprint is small (a static ~4 MB binary, gossip, and a handful
of QUIC connections). Most of a client's disk is its own data - wallet and
message history - which it keeps itself and which grows with use.

### Validator node (role not implemented yet - estimates)

Signs the first spend of each coin and keeps a nullifier store (markers of spent
coins, not a ledger or chain). Validators form an authenticated full-mesh
(<= 100 peers) with SWIM + Lifeguard liveness. The role must be always-on,
low-latency, and publicly reachable.

| Resource | Minimum (estimate) | Comfortable (estimate) |
|----------|--------------------|------------------------|
| CPU      | 2 cores | 4+ cores (headroom for post-quantum signatures) |
| RAM      | 2 GB    | 4 - 8 GB |
| Disk     | 20 GB SSD/NVMe | 50+ GB NVMe |
| Network  | static public IPv4 and/or IPv6, open UDP port, low latency, ~10 Mbit/s | symmetric, more headroom |
| Uptime   | 24/7, stable | - |

Where these come from:

- CPU is signature-bound (verify and sign on the spend path). Ed25519 is cheap;
  the planned post-quantum signatures are larger and heavier, hence the headroom.
- RAM holds the ~100 persistent mesh connections plus a hot index over the
  nullifier store.
- Disk grows monotonically with spent coins (hashes, bounded by spend volume -
  there is no block history, since there is no chain). Put it on SSD/NVMe
  because lookups sit on the latency-critical spend path.
- A validator is part of a small full-mesh and answers spend requests, so it
  needs a routable address (no NAT), an open UDP port, a stable low-latency
  link, and NTP-synced time for liveness and quorum timing.
- The validator signing key is high value: the packaged systemd unit already
  sandboxes the service, and stronger key custody (HSM, offline signing) is a
  later consideration.

The keeper (paid encrypted storage) and transmitter (relay) roles will get their
own profiles - storage-heavy and bandwidth-heavy respectively - when they land.
