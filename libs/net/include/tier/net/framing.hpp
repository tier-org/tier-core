#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/crypto/primitives.hpp"

namespace tier::net::framing {

// The wire frame is a 4-byte big-endian length prefix followed by that many
// payload bytes. A frame longer than this is refused: the bytes come from an
// untrusted peer and must not drive an unbounded allocation or buffer.
inline constexpr std::uint32_t kMaxFrameLen = 65536;

enum class FrameStatus : std::uint8_t {
  ok,          // a whole frame is available at the front of the buffer
  incomplete,  // need more bytes before a frame can be taken
  oversize,    // the length prefix exceeds kMaxFrameLen: fatal, drop the peer
};

struct TakeResult {
  FrameStatus status = FrameStatus::incomplete;
  std::size_t consumed = 0;     // bytes the whole frame occupies (prefix + body)
  std::size_t payload_off = 0;  // offset of the body within the buffer
  std::size_t payload_len = 0;  // body length
};

// Try to peel one length-prefixed frame off the front of `buf`. Pure and
// bounds-checked: it reads only what the prefix allows and never trusts the
// length past kMaxFrameLen. The caller consumes `consumed` bytes on ok.
[[nodiscard]] inline TakeResult take_frame(
    std::span<const tier::crypto::Byte> buf) noexcept {
  if (buf.size() < 4) {
    return {FrameStatus::incomplete, 0, 0, 0};
  }
  const std::uint32_t len = (static_cast<std::uint32_t>(buf[0]) << 24) |
                            (static_cast<std::uint32_t>(buf[1]) << 16) |
                            (static_cast<std::uint32_t>(buf[2]) << 8) |
                            static_cast<std::uint32_t>(buf[3]);
  if (len > kMaxFrameLen) {
    return {FrameStatus::oversize, 0, 0, 0};
  }
  if (buf.size() - 4 < len) {
    return {FrameStatus::incomplete, 0, 0, 0};
  }
  return {FrameStatus::ok, static_cast<std::size_t>(4) + len, 4, len};
}

}  // namespace tier::net::framing
