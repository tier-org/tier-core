#pragma once

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// SHA-256 of the input. The only hash in v0; used, among other things, to
// derive a fixed-size peer id from a (possibly large, algorithm-dependent)
// public key. Throws std::runtime_error on backend failure.
[[nodiscard]] Digest256 sha256(ByteSpan data);

}  // namespace tier::crypto
