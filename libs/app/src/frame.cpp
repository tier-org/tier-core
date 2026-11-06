#include "tier/app/frame.hpp"

#include <algorithm>

namespace tier::app {
namespace {

// [u8 version][u16 type BE][u8 flags][16 msg_id] = 20 bytes.
constexpr std::size_t kHeaderLen = 1 + 2 + 1 + kMsgIdLen;

}  // namespace

std::vector<std::uint8_t> encode_app_frame(const AppFrame& frame) {
  std::vector<std::uint8_t> out;
  out.reserve(kHeaderLen + frame.payload.size());
  out.push_back(kAppFrameVersion);
  const auto t = static_cast<std::uint16_t>(frame.type);
  out.push_back(static_cast<std::uint8_t>(t >> 8));
  out.push_back(static_cast<std::uint8_t>(t & 0xff));
  out.push_back(frame.flags);
  out.insert(out.end(), frame.msg_id.begin(), frame.msg_id.end());
  out.insert(out.end(), frame.payload.begin(), frame.payload.end());
  return out;
}

std::optional<AppFrame> decode_app_frame(std::span<const std::uint8_t> in) {
  if (in.size() < kHeaderLen) {
    return std::nullopt;
  }
  if (in[0] != kAppFrameVersion) {
    return std::nullopt;
  }
  AppFrame f;
  f.type = static_cast<AppType>((static_cast<std::uint16_t>(in[1]) << 8) | in[2]);
  f.flags = in[3];
  std::copy(in.begin() + 4, in.begin() + 4 + static_cast<std::ptrdiff_t>(kMsgIdLen),
            f.msg_id.begin());
  f.payload.assign(in.begin() + static_cast<std::ptrdiff_t>(kHeaderLen), in.end());
  return f;
}

}  // namespace tier::app
