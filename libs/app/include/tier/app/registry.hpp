#pragma once

#include <cstddef>
#include <cstdint>

// The single source of truth for application message type ids (layer 2, see
// docs/app-protocol.md). Adding a type reserves an id here and adds a handler;
// no existing handler is touched. Ranges:
//   0x0001-0x00ff  core / system types (reserved to this repo)
//   0x0100-0x0fff  first-party application types
//   0x1000-0xffff  reserved / experimental
namespace tier::app {

// The base type is fixed at 16 bits by the wire format (the frame's type field
// is a u16), not by the current value set, so the enum-size check does not apply.
// NOLINTNEXTLINE(performance-enum-size)
enum class AppType : std::uint16_t {
  text = 0x0001,              // chat text; payload is UTF-8; wants_receipt
  delivery_receipt = 0x0002,  // system; payload is the acked msg_id; no receipt
};

// Application-frame version, independent of the transport and envelope versions.
inline constexpr std::uint8_t kAppFrameVersion = 1;

// Frame flags (one byte). bit0: the sender wants a delivery receipt.
inline constexpr std::uint8_t kFlagWantsReceipt = 0x01;

// Length of a message correlation id, in bytes.
inline constexpr std::size_t kMsgIdLen = 16;

}  // namespace tier::app
