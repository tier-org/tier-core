#pragma once

#include <array>
#include <cstddef>
#include <optional>

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// X25519 ECDH (RFC 7748). 32-byte keys; the secret is the raw clamped scalar.
inline constexpr std::size_t kX25519KeySize = 32;

using X25519PublicKey = std::array<Byte, kX25519KeySize>;
using X25519SecretKey = std::array<Byte, kX25519KeySize>;

struct X25519KeyPair {
  X25519SecretKey secret{};
  X25519PublicKey public_key{};
};

// Fresh ephemeral keypair from the system CSPRNG. Throws std::runtime_error on
// backend failure.
[[nodiscard]] X25519KeyPair x25519_generate();

// Derive the public key for a given 32-byte secret scalar (used for the
// static, seed-derived identity key). Throws on backend failure.
[[nodiscard]] X25519KeyPair x25519_from_secret(const X25519SecretKey& secret);

// Raw X25519 shared secret of our secret and the peer's public key. Returns
// std::nullopt if the result is rejected (e.g. a low-order peer key yields the
// all-zero shared secret, which OpenSSL reports as an error): an open path must
// treat this as a decryption failure, not crash. Throws only on an unexpected
// backend setup failure.
[[nodiscard]] std::optional<std::array<Byte, kX25519KeySize>> x25519_ecdh(
    const X25519SecretKey& secret, const X25519PublicKey& peer_public);

}  // namespace tier::crypto
