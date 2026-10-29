# tier-core

Core node for Tier, a decentralized network for encrypted messaging and payments.

**Status:** early scaffold. The networking base layer (QUIC over ngtcp2 with
aws-lc) is not implemented yet.

## Layout

- `libs/core` — transport-agnostic core (sans-I/O state machines)
- `libs/crypto` — cryptographic seam (signing / KEX / hash), backed by aws-lc
- `libs/net` — QUIC networking (ngtcp2 + aws-lc) *(pending)*
- `apps/node` — node daemon
- `apps/cli` — command-line client
- `tests` — unit tests (CTest)
- `fuzz` — libFuzzer targets for untrusted-input decoders (Clang only)

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    cmake --build build -j
    ctest --test-dir build --output-on-failure

AddressSanitizer and UndefinedBehaviorSanitizer are on by default
(`-DTIER_SANITIZE=OFF` to disable). Warnings are errors by default
(`-DTIER_WERROR=OFF` to relax). Fuzz targets build with `-DTIER_FUZZ=ON` under Clang.
