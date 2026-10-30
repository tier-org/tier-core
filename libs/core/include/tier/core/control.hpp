#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "tier/core/membership.hpp"

namespace tier::core {

// Control-plane (node-to-node) message types. More are added as the base layer
// grows (SWIM ping/ack, etc.); v0 carries only a membership snapshot.
enum class ControlType : std::uint8_t { membership = 1 };

// Encode a membership snapshot as a control message:
//   [type:1][count:4 BE]( [id:32][role:1][incarnation:8 BE][liveness:1]
//                          [addr_len:2 BE][addr:addr_len] )*
std::vector<std::uint8_t> encode_membership_message(
    const std::vector<PeerInfo>& peers);

// Decode a membership control message. Returns std::nullopt on any malformed or
// out-of-bounds input (this is a decoder of untrusted bytes; it must never
// crash and never trust a length). Trailing bytes are rejected.
std::optional<std::vector<PeerInfo>> decode_membership_message(
    std::span<const std::uint8_t> in);

// Bounds (reject absurd inputs rather than allocate on an attacker's word).
inline constexpr std::uint32_t kMaxPeersPerMessage = 4096;
inline constexpr std::uint16_t kMaxAddressLen = 256;

}  // namespace tier::core
