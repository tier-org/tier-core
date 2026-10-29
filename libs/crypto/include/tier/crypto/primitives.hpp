#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace tier::crypto {

using Byte = std::uint8_t;
using ByteSpan = std::span<const Byte>;

// SHA-256 is the only hash in v0; it is provided by the libcrypto backend.
inline constexpr std::size_t kDigest256Size = 32;
using Digest256 = std::array<Byte, kDigest256Size>;

}  // namespace tier::crypto
