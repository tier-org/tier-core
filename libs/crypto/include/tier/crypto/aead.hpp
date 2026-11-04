#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <vector>

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// ChaCha20-Poly1305 AEAD (RFC 8439). Fixed 256-bit key, 96-bit nonce, 128-bit
// tag. The caller must never reuse a (key, nonce) pair; the message layer uses
// a fresh random nonce per message.
inline constexpr std::size_t kAeadKeySize = 32;
inline constexpr std::size_t kAeadNonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;

using AeadKey = std::array<Byte, kAeadKeySize>;
using AeadNonce = std::array<Byte, kAeadNonceSize>;

// Encrypt `plaintext` with `aad` authenticated-but-not-encrypted. Returns
// ciphertext followed by the 16-byte tag (length = plaintext size + 16). Throws
// std::runtime_error on backend failure.
[[nodiscard]] std::vector<Byte> aead_seal(const AeadKey& key,
                                          const AeadNonce& nonce, ByteSpan aad,
                                          ByteSpan plaintext);

// Decrypt and verify. `ciphertext` is the sealed output (ciphertext || tag).
// Returns the plaintext, or std::nullopt if `ciphertext` is shorter than the
// tag or authentication fails (wrong key/nonce/aad or tampering). Never throws
// on an authentication failure - that is an expected, attacker-triggerable
// outcome and must be a value, not an exception.
[[nodiscard]] std::optional<std::vector<Byte>> aead_open(const AeadKey& key,
                                                         const AeadNonce& nonce,
                                                         ByteSpan aad,
                                                         ByteSpan ciphertext);

}  // namespace tier::crypto
