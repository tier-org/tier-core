# tier-core

Core node for Tier, a decentralized network for encrypted messaging and payments.

**Status:** early scaffold. The QUIC transport (ngtcp2 + OpenSSL) with mutual
TLS 1.3 authentication and certificate-bound node identity handshakes, and the
gossip/membership layer (SWIM) runs on top of it. NAT traversal (hole punching)
and the relay node role are not implemented yet.

## Layout

- `libs/core` - transport-agnostic core (sans-I/O state machines)
- `libs/crypto` - cryptographic seam (signing / KEX / hash), backed by OpenSSL
- `libs/net` - QUIC networking (ngtcp2 + OpenSSL)
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

The TLS 1.3 **key exchange is post-quantum hybrid by default**: the handshake
offers `X25519MLKEM768:X25519`, so it prefers hybrid X25519 + ML-KEM-768 and
falls back to classical X25519 only against a peer that cannot do the hybrid
group (`test_endpoint` asserts the hybrid group is negotiated). This protects
session confidentiality against "harvest now, decrypt later": recorded traffic
is not decryptable by a future quantum adversary even though the long-term
identity keys are classical.

Post-quantum **signatures**, by contrast, are **experimental and unsupported**.
Node identity stays Ed25519; ML-DSA is planned behind the same
algorithm-agnostic signing interface but is **not** enabled, and **no guarantees
whatsoever** are made about it - on-wire formats, interoperability, and security
properties may change or break at any time.

The design goal is crypto-agility: every key, signature, and certificate is
meant to carry an explicit algorithm identifier; a verifier supports a *set* of
algorithms rather than one; and any network-wide change of the algorithm that
peers *produce* is a coordinated activation, never a simultaneous flag day.
Peers may therefore run different algorithms as long as each side can verify
what the other presents. Ed25519 (classical) is quantum-vulnerable; this is
accepted for v0 and addressed by the planned migration path, not by the current
default.

## Encrypted messaging

Participants can send each other **end-to-end encrypted application messages**
over the control plane (`tierctl send` / `inbox`, or the `Node::send_message` /
`take_inbox` API). The message is sealed to the recipient's published encryption
keys and signed by the sender's Ed25519 identity, so the recipient gets both
confidentiality (only it can decrypt) and sender authenticity (it learns who
sent it and that nothing was altered).

Three cipher suites are offered; the sender picks one per message:

- **classical** - X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305.
- **hybrid** (default) - X25519 **and** ML-KEM-768, both shared secrets folded
  into the KDF, so the message stays secure if either primitive is later broken.
- **pq** - ML-KEM-768 only, for a fully post-quantum posture.

Each node's encryption keys (an X25519 key and an ML-KEM-768 key) are derived
deterministically from its one Ed25519 identity seed, so there is no extra key
file. A node announces its encryption public keys to each peer on connect, in an
owner-signed message the peer verifies against the identity it authenticated
with in the QUIC handshake - the large ML-KEM key therefore never travels in the
gossiped membership table.

Reaching a peer you are not already connected to uses the **communicator** role
(see docs/communicator.md). Two plain clients never dial or gossip each other,
so to be reachable a client publishes an owner-signed **presence record** - its
addresses and encryption keys - to the communicator(s) responsible for its id
(rendezvous hashing). Another node resolves it by asking the same communicator,
then connects directly and the sealed message flows. `send_message` returns
`sent` when the peer was already connected, or `queued` when it is being
resolved and connected on demand (delivered, or dropped after a timeout). This
is direct, relay-free delivery between clients; data never passes through the
communicator, only the small presence lookup does.

### User identity over device identity

A user identity (its own Ed25519 keypair) sits above the device identity, so one
user can span several devices and a recipient learns which *user* sent a
message, not merely which device (see docs/multi-identity.md). The user key signs
a device credential authorizing each device; that credential travels in a user
envelope inside the normal sealed message. User identities are managed entirely
at runtime over the admin socket (`tierctl user add [seed]` to generate or
import, `tierctl user ls`, `tierctl user rm <user-id>`); a node may host several
at once and they persist across restarts. A device-to-device `send` carries no
user layer; `tierctl send-user <from-user> <to-user>` sends from one of your
local users to a user id, enrolling each user at a communicator so it is
addressable and fanning the message out to the recipient's online devices (a
recipient hosted on the same node is delivered locally). With no message storage
in this version, both sender and recipient must be online.

Still future work: offline store-and-forward (keeper-backed, so an offline
device can catch up), forward-secret sessions (a ratchet) and group messaging.
The sealing itself is independent of how a message is carried. Per-message ephemeral X25519
already gives forward secrecy for the classical key-agreement part.

## Dependencies

Build-time:

- a C++20 compiler (GCC >= 11 or Clang >= 14)
- CMake >= 3.25 and a generator (Ninja or Make). Ubuntu 24.04 ships a new
  enough CMake; Ubuntu 22.04 ships 3.22, so install a newer one there (pip,
  snap, or Kitware's apt repo).
- Git, for the vendored submodules
- Perl, to build the vendored OpenSSL (its `Configure` is a Perl script)
- for packaging a `.deb`: `dpkg-dev` and `file`

On Debian/Ubuntu: `apt-get install build-essential cmake git ninja-build perl`.

OpenSSL (3.5) and ngtcp2 are vendored as git submodules under `vendor/` and
built from source, so clone with submodules:

    git clone --recurse-submodules <url>
    # or, in an existing checkout:
    git submodule update --init --recursive

Runtime: only `libc6`. OpenSSL, ngtcp2, libstdc++ and libgcc are linked
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

`build/apps/node/tierd` then links only against glibc (`ldd` shows just
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

    sudo dpkg -i tierd_X.Y.Z_amd64.deb
    sudoedit /etc/tier/tierd.env      # set TIER_ARGS: listen port, optional seed
    sudo systemctl start tierd

The node stores its Ed25519 identity under `/var/lib/tier` (systemd
StateDirectory). It joins through the preconfigured seeds below, so no seed
argument is required; an explicit `<seed_ip> <seed_port>` in `TIER_ARGS` is
dialed in addition.

### Cutting a release

The top-level `VERSION` file is the single source of truth for the version
(CMake reads it; the binary reports it). Do not edit `VERSION` by hand: bump it
only through the script, which also makes the commit and the matching tag so the
file and the tag can never drift:

    scripts/release.sh <X.Y.Z | patch | minor | major> [--push]

It validates the bump (semver, strictly forward, clean tree on `main` in sync
with origin, tag not already taken), writes `VERSION`, commits it as `X.Y.Z`,
and tags the commit `vX.Y.Z`. Without `--push` it stops there and prints the
push command; `--push` pushes the commit and the tag, which triggers the release
workflow. That workflow refuses to build if `VERSION` does not match the tag.

## Networks

Every node belongs to exactly one **network** (cluster). `mainnet` is the
default and the production network; `testnet` is reserved for a public test
network; any other name is a **private** network. The four nodes the project
runs today are `mainnet`.

The network is chosen by the `TIER_NETWORK` environment variable (unset =
`mainnet`). A name is a short DNS-style label - lowercase letters, digits and
hyphens, 1-32 characters - and an invalid value is rejected at startup rather
than silently stranding the node.

Networks are **isolated at the transport layer**: the network name is folded
into the QUIC/TLS ALPN token (`tier/0/<network>`), so two nodes on different
networks cannot complete a handshake and therefore never exchange membership -
even if they share a seed address, and even on the same host. The network choice
also selects which preconfigured seeds a node dials (below). Isolation does not
depend on seed separation; it is enforced by the handshake.

The network selects which preconfigured seeds a node dials, its handshake
isolation, and its software-version policy (below); more per-network parameters
may be added later. Private networks are first-class:
pick a name, point the nodes at each other with `TIER_SEEDS`, and the cluster is
isolated from mainnet by construction.

## Network seeds

The bootstrap seeds are compiled into the binary **per network** -
`libs/core/include/tier/core/seeds.hpp` is the single source of truth. `mainnet`
ships the production seeds; `testnet` and private networks have none baked in and
join via `TIER_SEEDS`. There is no runtime fetch (no DNS seed list, no HTTPS), so
joining adds no extra point of failure; the baked set changes only by editing
that file and cutting a new release.

A fresh node dials every seed at startup over whichever family it has (IPv6
preferred). Reaching one seed is enough - the rest of the membership arrives by
anti-entropy. Each seed is listed with both an IPv4 and an IPv6 address on UDP
port 7777; a node that is itself a seed skips its own address, and a connection
to self is dropped regardless. Seed identities are not pinned: a peer's identity
is authenticated by the TLS handshake, so a wrong address fails closed rather
than impersonating a seed (key pinning is a possible later hardening).

The `TIER_SEEDS` environment variable **fully replaces** the compiled-in list
for private networks and local testing: when set and non-empty the node dials
only those addresses and never the production seeds (an override that parses to
nothing leaves the node isolated rather than falling back, so a test net can
never leak onto the real network). It is comma/space separated, `ip:port` with
IPv6 bracketed, e.g. `TIER_SEEDS="[fd00::2]:7777 10.0.0.2:7777"`. This is local
static configuration, not a runtime fetch, so it preserves the no-extra-point-of-
failure property.

`TIER_SEEDS` and `TIER_NETWORK` are orthogonal: the first sets *which addresses*
to dial, the second sets *which cluster* a node belongs to (and thus which peers
it will handshake with). A private network is typically both - a name plus the
addresses of its own nodes.

## Version policy (per network)

Each node advertises its software version (`tier::core::version()`), and it is
gossiped mesh-wide, so `tierctl peers` shows every peer's version. On top of that
each network carries a **version window** - the range of versions allowed to
participate - expressed as `min,max` with **min inclusive and max exclusive**.
So `1.4.0,1.5.0` accepts every `1.4.x` and rejects `1.5.0`: the pessimistic
"pin the minor, take the patches" window (like a bundler `~> 1.4.0`). Either
bound may be empty for an open side (`1.4.0,` is `>= 1.4.0`, `,2.0.0` is
`< 2.0.0`); empty is unconstrained.

The window for each public network lives in a dedicated file under the top-level
[`networks/`](networks/) directory (one file per network) - the single source of
truth. These files are both **baked into the binary at build time** (CMake reads
them and generates a compiled table; the binary never reads them at runtime, the
same discipline as the seeds) and **parsed directly by external tooling** - e.g.
an automation job that watches whether a freshly released version falls inside a
public network's window. `tierd networks` prints what the running binary baked:

    $ tierd networks
    NETWORK               VERSION POLICY
    mainnet               unconstrained
    testnet               unconstrained

A private network has no file there; it is unconstrained unless its operator sets
`TIER_VERSION_RANGE` (the override also serves local testing). No public network
is pinned yet - the files are unconstrained so the running production nodes
(0.2.4) are not locked out, and governance sets real windows by editing those
files and cutting a release.

The policy is enforced in two places: a node whose own version is outside its
network's window **refuses to start** (fails closed), and a gossiped peer outside
the window is **not admitted** to membership (an unknown or pre-version peer is
admitted leniently, so a mixed fleet is never partitioned by it).

This is cluster **governance, not a security boundary**: a version is
self-reported, so the window gates honest misconfiguration and lets governance
freeze or retire a version. Hard protocol incompatibility between builds that
genuinely cannot interoperate is a separate concern, enforced at the handshake by
the network's ALPN token, not here. The window is local policy and is never sent
on the wire, so changing it needs no coordinated flag day. It is orthogonal to
`TIER_NETWORK` and `TIER_SEEDS`.

### Local mesh and the e2e gate

`test/net/` brings up a four-node, dual-stack mesh on an internal (no-internet)
Docker network, on the private `localnet` network and seeded via `TIER_SEEDS`,
so it is doubly isolated from production (no route to it, and a different ALPN):

    make localnet-up      # start a local mesh to poke by hand
    make localnet-status  # `tierctl peers` on every node
    make localnet-down

    make e2e              # converge, assert full discovery + dual-stack, tear down

`make e2e` exits non-zero unless every node discovers the whole mesh and
advertises both address families; run it before cutting a release. It needs
Docker with IPv6 enabled on the daemon - see `test/net/README.md`.

## Diagnostics (tierctl)

The daemon exposes a local admin socket (default `/run/tierd/tierd.sock`, or
`$TIER_ADMIN_SOCK`). `tierctl` talks to it over that socket:

    sudo tierctl id           # this node's device id (64 hex)
    sudo tierctl peers        # the node's view of the mesh: known vs connected
    sudo tierctl inbox        # print and drain encrypted messages received
    sudo tierctl send <peer-id> [classical|hybrid|pq] <message>
    sudo tierctl user add [seed]      # host a user identity (prints its user id)
    sudo tierctl user ls              # list hosted user ids
    sudo tierctl user rm <user-id>    # stop hosting a user identity
    sudo tierctl send-user <from-user> <to-user> [classical|hybrid|pq] <message>

`send` encrypts a message end-to-end (see "Encrypted messaging" below);
`<peer-id>` is the recipient's full 64-hex id - get it from `tierctl id` on that
node and share it out of band (the `peers` table shows only a shortened id). The
suite defaults to `hybrid`. If the peer is not already connected, the node
resolves it through a communicator and connects on demand, so `send` reports the
message accepted (sent or queued). `send-user` instead sends from one of this
node's hosted users (`user add`/`ls`/`rm` manage them at runtime) to a user id,
fanning out to that user's online devices; `inbox` prints each received message
with its authenticated sender (and, for a user message, the sending user and the
local user it was addressed to) and suite, then clears the queue.

The header reports the node's own network (the cluster it joined) and the known
versus connected counts. Each row is a peer: short id, whether a live connection
is held, liveness, roles, the peer's advertised software version (gossiped
mesh-wide, so skew is visible at a glance; `-` for a peer too old to advertise
one) and advertised addresses. The network is a header, not a column: membership
only ever holds peers on this same network, so every row shares it. The socket is
local only (service user and root) and is never exposed on the network.
The wire is the project's compact binary codec, one request and one response per
connection.

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
The **communicator** role is reachable backbone that additionally serves the
client-to-client presence registry (and, later, hole-punch signaling); set it
with `TIER_ROLES=communicator`. See docs/communicator.md.

## License

Apache License 2.0 (see `LICENSE` and `NOTICE`). Commercial use, use in open or
closed source, and redistribution are permitted; keep the `NOTICE` attribution.
Vendored components keep their own licenses: OpenSSL 3.5 (Apache-2.0) and ngtcp2
(MIT), both permissive.
