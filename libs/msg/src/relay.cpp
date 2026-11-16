#include "tier/msg/relay.hpp"

#include <cstring>

#include "tier/core/control.hpp"

namespace tier::msg {
namespace {

using tier::crypto::Byte;

constexpr std::uint8_t kRelayType =
    static_cast<std::uint8_t>(tier::core::ControlType::relay_data);

}  // namespace

std::vector<Byte> make_relay_frame(const tier::core::PeerId& dst,
                                   const tier::crypto::Ed25519PublicKey& src_key,
                                   ByteSpan sealed) {
  std::vector<Byte> out;
  out.reserve(1 + dst.size() + src_key.size() + sealed.size());
  out.push_back(kRelayType);
  out.insert(out.end(), dst.begin(), dst.end());
  out.insert(out.end(), src_key.begin(), src_key.end());
  out.insert(out.end(), sealed.begin(), sealed.end());
  return out;
}

std::optional<RelayFrame> open_relay_frame(ByteSpan message) {
  RelayFrame f;
  const std::size_t header = 1 + f.dst.size() + f.src_key.size();
  if (message.size() < header || message[0] != kRelayType) {
    return std::nullopt;
  }
  std::size_t pos = 1;
  std::memcpy(f.dst.data(), message.data() + pos, f.dst.size());
  pos += f.dst.size();
  std::memcpy(f.src_key.data(), message.data() + pos, f.src_key.size());
  pos += f.src_key.size();
  f.sealed = message.subspan(pos);
  return f;
}

}  // namespace tier::msg
