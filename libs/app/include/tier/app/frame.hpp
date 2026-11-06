#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "tier/app/registry.hpp"

namespace tier::app {

// An application frame: the inner plaintext of a user envelope (layer 2). On the
// wire (see docs/app-protocol.md):
//   [u8 version][u16 type BE][u8 flags][16 msg_id][payload...]
// The frame sits inside the sealed transport message and inside the user
// envelope, both sealed to the recipient device, so type/flags/msg_id/payload
// are confidential to a relaying communicator.
struct AppFrame {
  AppType type{};
  std::uint8_t flags = 0;
  std::array<std::uint8_t, kMsgIdLen> msg_id{};
  std::vector<std::uint8_t> payload;

  [[nodiscard]] bool wants_receipt() const noexcept {
    return (flags & kFlagWantsReceipt) != 0;
  }
};

std::vector<std::uint8_t> encode_app_frame(const AppFrame& frame);

// Decode a frame. std::nullopt on a short buffer (< header) or an unknown
// version. The type is accepted as-is (dispatch decides if it is known), so an
// unrecognized type still decodes and is counted rather than crashing.
std::optional<AppFrame> decode_app_frame(std::span<const std::uint8_t> in);

}  // namespace tier::app
