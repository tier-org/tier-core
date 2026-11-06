#pragma once

#include <optional>
#include <string>

#include "tier/core/membership.hpp"

namespace tier::messenger {

// Full 64-char lowercase hex of a 32-byte id.
inline std::string to_hex(const tier::core::PeerId& id) {
  static const char* const hex = "0123456789abcdef";
  std::string out;
  out.reserve(id.size() * 2);
  for (const auto b : id) {
    out += hex[b >> 4];
    out += hex[b & 0x0F];
  }
  return out;
}

// First 8 bytes (16 hex) - a short, human-scannable prefix.
inline std::string short_hex(const tier::core::PeerId& id) {
  return to_hex(id).substr(0, 16);
}

// Parse exactly 64 hex chars into a 32-byte id. nullopt otherwise.
inline std::optional<tier::core::PeerId> from_hex(const std::string& s) {
  if (s.size() != tier::core::PeerId{}.size() * 2) {
    return std::nullopt;
  }
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  tier::core::PeerId id{};
  for (std::size_t i = 0; i < id.size(); ++i) {
    const int hi = nib(s[2 * i]);
    const int lo = nib(s[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    id[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return id;
}

}  // namespace tier::messenger
