#pragma once

#include <cstddef>
#include <cstdint>
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

// PBKDF2-HMAC-SHA256 (RFC 8018). Derives `out_len` bytes from `password` and
// `salt` over `iterations` rounds. Unlike HKDF this is deliberately slow (the
// iteration count is the work factor), so it is for stretching a low-entropy
// human secret - the messenger's local device-lock passphrase. `salt` may be
// empty but should not be. Throws std::runtime_error on backend failure, or if
// `out_len` or `iterations` is zero.
[[nodiscard]] std::vector<Byte> pbkdf2_sha256(ByteSpan password, ByteSpan salt,
                                              std::uint32_t iterations,
                                              std::size_t out_len);

}  // namespace tier::crypto
