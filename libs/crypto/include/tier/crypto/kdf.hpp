#pragma once

#include <cstddef>
#include <vector>

#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// HKDF (RFC 5869) with SHA-256, extract-and-expand in one shot. Derives
// `out_len` bytes of key material from input keying material `ikm`, an optional
// `salt` and an optional context `info`. `salt`/`info` may be empty. Throws
// std::runtime_error on backend failure or if `out_len` exceeds HKDF's limit
// (255 * 32 bytes for SHA-256).
[[nodiscard]] std::vector<Byte> hkdf_sha256(ByteSpan ikm, ByteSpan salt,
                                            ByteSpan info, std::size_t out_len);

}  // namespace tier::crypto
