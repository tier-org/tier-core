#pragma once

#include <array>
#include <cstddef>
#include <optional>

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// ML-KEM-768 (FIPS 203) key encapsulation. Sizes are fixed by the parameter
// set: 1184-byte encapsulation (public) key, 1088-byte ciphertext, 32-byte
// shared secret, 64-byte keygen seed (d || z).
inline constexpr std::size_t kMlKem768PublicKeySize = 1184;
inline constexpr std::size_t kMlKem768CiphertextSize = 1088;
inline constexpr std::size_t kMlKem768SharedSecretSize = 32;
inline constexpr std::size_t kMlKem768SeedSize = 64;

using MlKem768PublicKey = std::array<Byte, kMlKem768PublicKeySize>;
using MlKem768Ciphertext = std::array<Byte, kMlKem768CiphertextSize>;
using MlKem768SharedSecret = std::array<Byte, kMlKem768SharedSecretSize>;
using MlKem768Seed = std::array<Byte, kMlKem768SeedSize>;

// A decapsulation keypair: the 64-byte secret seed (treat as sensitive) and the
// public key derived from it. Keygen is deterministic in the seed, so the same
// seed always yields the same keypair - this is how the identity's PQ key is
// reproduced from the one stored identity seed.
struct MlKem768KeyPair {
  MlKem768Seed seed{};
  MlKem768PublicKey public_key{};
};

// Deterministic keygen from a 64-byte seed. Throws std::runtime_error on
// backend failure.
[[nodiscard]] MlKem768KeyPair mlkem768_from_seed(const MlKem768Seed& seed);

struct MlKem768Encapsulation {
  MlKem768Ciphertext ciphertext{};
  MlKem768SharedSecret shared_secret{};
};

// Encapsulate to a public key: produces a ciphertext and the shared secret the
// holder of the matching secret key will recover. Uses the system CSPRNG, so
// each call differs. Throws on backend failure (including a malformed public
// key the backend rejects).
[[nodiscard]] MlKem768Encapsulation mlkem768_encapsulate(
    const MlKem768PublicKey& public_key);

// Decapsulate a ciphertext with the keypair's secret. ML-KEM decapsulation is
// designed never to fail on a malformed ciphertext - it returns an
// (unpredictable) shared secret instead (implicit rejection), so the AEAD step
// above is what actually rejects a bad ciphertext. Returns std::nullopt only on
// an unexpected backend failure.
[[nodiscard]] std::optional<MlKem768SharedSecret> mlkem768_decapsulate(
    const MlKem768Seed& seed, const MlKem768Ciphertext& ciphertext);

}  // namespace tier::crypto
