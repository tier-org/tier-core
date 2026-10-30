#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "tier/core/membership.hpp"

namespace tier::core {

// Control-plane (node-to-node) message types.
//   membership - an anti-entropy snapshot of the known-peers table.
//   ping/ack   - SWIM direct liveness probe and its reply.
//   ping_req   - SWIM indirect probe: "ping this target for me and relay its ack".
enum class ControlType : std::uint8_t {
  membership = 1,
  ping = 2,
  ack = 3,
  ping_req = 4,
};

// Peek the control type of a received message without decoding it. Returns
// std::nullopt on an empty message or an unknown type byte.
std::optional<ControlType> peek_control_type(std::span<const std::uint8_t> in);

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

// --- SWIM probe messages ---------------------------------------------------
// ping/ack:  [type:1][seq:8 BE]
// ping_req:  [type:1][seq:8 BE][target:32]
// `seq` matches an ack to the probe that caused it; `target` names the peer the
// relay should ping on the requester's behalf.

struct PingMessage {
  std::uint64_t seq = 0;
};
struct AckMessage {
  std::uint64_t seq = 0;
};
struct PingReqMessage {
  std::uint64_t seq = 0;
  PeerId target{};
};

std::vector<std::uint8_t> encode_ping(std::uint64_t seq);
std::vector<std::uint8_t> encode_ack(std::uint64_t seq);
std::vector<std::uint8_t> encode_ping_req(std::uint64_t seq, const PeerId& target);

// Decoders of untrusted bytes: std::nullopt on any malformed input, no crash,
// trailing bytes rejected.
std::optional<PingMessage> decode_ping(std::span<const std::uint8_t> in);
std::optional<AckMessage> decode_ack(std::span<const std::uint8_t> in);
std::optional<PingReqMessage> decode_ping_req(std::span<const std::uint8_t> in);

// Bounds (reject absurd inputs rather than allocate on an attacker's word).
inline constexpr std::uint32_t kMaxPeersPerMessage = 4096;
inline constexpr std::uint16_t kMaxAddressLen = 256;

}  // namespace tier::core
