#pragma once

#include <vector>

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// Algorithm-agnostic signing seam. v0 is backed by Ed25519, but the same
// interface must accept post-quantum schemes (e.g. ML-DSA) later, so keys and
// signatures are variable-size. Concrete implementations wrap the libcrypto
// backend and are added in a later step.

class Verifier {
 public:
  virtual ~Verifier() = default;
  [[nodiscard]] virtual bool verify(ByteSpan message, ByteSpan signature) const = 0;
};

class Signer {
 public:
  virtual ~Signer() = default;
  [[nodiscard]] virtual std::vector<Byte> sign(ByteSpan message) const = 0;
  [[nodiscard]] virtual std::vector<Byte> public_key() const = 0;
};

}  // namespace tier::crypto
