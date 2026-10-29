# tier-core

Core node for Tier, a decentralized network for encrypted messaging and payments.

**Status:** early scaffold. The QUIC transport (ngtcp2 + wolfSSL) with mutual
TLS 1.3 authentication and certificate-bound node identity handshakes; the
gossip/membership layer above it is not implemented yet.

## Layout

- `libs/core` - transport-agnostic core (sans-I/O state machines)
- `libs/crypto` - cryptographic seam (signing / KEX / hash), backed by wolfSSL
- `libs/net` - QUIC networking (ngtcp2 + wolfSSL) *(pending)*
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

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    cmake --build build -j
    ctest --test-dir build --output-on-failure

AddressSanitizer and UndefinedBehaviorSanitizer are on by default
(`-DTIER_SANITIZE=OFF` to disable). Warnings are errors by default
(`-DTIER_WERROR=OFF` to relax). Fuzz targets build with `-DTIER_FUZZ=ON` under Clang.
