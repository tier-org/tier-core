#pragma once

#include <array>
#include <cstddef>
#include <vector>

#include "tier/crypto/primitives.hpp"
#include "tier/crypto/signature.hpp"

namespace tier::crypto {

inline constexpr std::size_t kEd25519PublicKeySize = 32;
inline constexpr std::size_t kEd25519SeedSize = 32;
inline constexpr std::size_t kEd25519SignatureSize = 64;

using Ed25519PublicKey = std::array<Byte, kEd25519PublicKeySize>;
using Ed25519Seed = std::array<Byte, kEd25519SeedSize>;

// Ed25519 signature verifier. Holds only the 32-byte public key; the backend
// key object is rebuilt per call, so no OpenSSL type appears in this header.
class Ed25519Verifier final : public Verifier {
 public:
  explicit Ed25519Verifier(const Ed25519PublicKey& public_key) noexcept;

  [[nodiscard]] bool verify(ByteSpan message, ByteSpan signature) const override;

  [[nodiscard]] const Ed25519PublicKey& public_key_bytes() const noexcept {
    return public_key_;
  }

 private:
  Ed25519PublicKey public_key_;
};

// Ed25519 signer. Holds the 32-byte secret seed (treat as sensitive) and the
// matching public key.
class Ed25519Signer final : public Signer {
 public:
  Ed25519Signer(const Ed25519Seed& seed, const Ed25519PublicKey& public_key) noexcept;

  [[nodiscard]] std::vector<Byte> sign(ByteSpan message) const override;
  [[nodiscard]] std::vector<Byte> public_key() const override;

  [[nodiscard]] const Ed25519PublicKey& public_key_bytes() const noexcept {
    return public_key_;
  }
  [[nodiscard]] const Ed25519Seed& seed() const noexcept { return seed_; }

 private:
  Ed25519Seed seed_;
  Ed25519PublicKey public_key_;
};

}  // namespace tier::crypto
