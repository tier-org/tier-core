#include "tier/core/control.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace tier::core {
namespace {

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFFU));
  }
}

// A bounds-checked cursor over the input; every read is guarded.
class Reader {
 public:
  explicit Reader(std::span<const std::uint8_t> in) noexcept : in_(in) {}

  [[nodiscard]] bool take(std::size_t n) noexcept {
    if (in_.size() - pos_ < n) {
      return false;
    }
    pos_ += n;
    return true;
  }

  [[nodiscard]] bool u8(std::uint8_t& out) noexcept {
    const std::size_t at = pos_;
    if (!take(1)) {
      return false;
    }
    out = in_[at];
    return true;
  }

  [[nodiscard]] bool u16(std::uint16_t& out) noexcept {
    const std::size_t at = pos_;
    if (!take(2)) {
      return false;
    }
    out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(in_[at]) << 8) |
                                     static_cast<std::uint16_t>(in_[at + 1]));
    return true;
  }

  [[nodiscard]] bool u32(std::uint32_t& out) noexcept {
    const std::size_t at = pos_;
    if (!take(4)) {
      return false;
    }
    out = (static_cast<std::uint32_t>(in_[at]) << 24) |
          (static_cast<std::uint32_t>(in_[at + 1]) << 16) |
          (static_cast<std::uint32_t>(in_[at + 2]) << 8) |
          static_cast<std::uint32_t>(in_[at + 3]);
    return true;
  }

  [[nodiscard]] bool u64(std::uint64_t& out) noexcept {
    const std::size_t at = pos_;
    if (!take(8)) {
      return false;
    }
    out = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      out = (out << 8) | static_cast<std::uint64_t>(in_[at + i]);
    }
    return true;
  }

  [[nodiscard]] bool bytes(std::size_t n, std::span<const std::uint8_t>& out) noexcept {
    const std::size_t at = pos_;
    if (!take(n)) {
      return false;
    }
    out = in_.subspan(at, n);
    return true;
  }

  [[nodiscard]] bool at_end() const noexcept { return pos_ == in_.size(); }

 private:
  std::span<const std::uint8_t> in_;
  std::size_t pos_ = 0;
};

}  // namespace

std::vector<std::uint8_t> encode_membership_message(
    const std::vector<PeerInfo>& peers) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::membership));
  put_u32(out, static_cast<std::uint32_t>(peers.size()));
  for (const PeerInfo& p : peers) {
    out.insert(out.end(), p.id.begin(), p.id.end());
    out.push_back(static_cast<std::uint8_t>(p.role));
    put_u64(out, p.incarnation);
    out.push_back(static_cast<std::uint8_t>(p.liveness));
    const auto addr_len =
        static_cast<std::uint16_t>(p.address.size() > kMaxAddressLen
                                       ? kMaxAddressLen
                                       : p.address.size());
    put_u16(out, addr_len);
    out.insert(out.end(), p.address.begin(), p.address.begin() + addr_len);
  }
  return out;
}

std::optional<std::vector<PeerInfo>> decode_membership_message(
    std::span<const std::uint8_t> in) {
  Reader r(in);

  std::uint8_t type = 0;
  if (!r.u8(type) || type != static_cast<std::uint8_t>(ControlType::membership)) {
    return std::nullopt;
  }

  std::uint32_t count = 0;
  if (!r.u32(count) || count > kMaxPeersPerMessage) {
    return std::nullopt;
  }

  std::vector<PeerInfo> peers;
  peers.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    PeerInfo p;

    std::span<const std::uint8_t> id_bytes;
    if (!r.bytes(p.id.size(), id_bytes)) {
      return std::nullopt;
    }
    std::copy(id_bytes.begin(), id_bytes.end(), p.id.begin());

    std::uint8_t role = 0;
    if (!r.u8(role) || role > static_cast<std::uint8_t>(Role::transmitter)) {
      return std::nullopt;
    }
    p.role = static_cast<Role>(role);

    if (!r.u64(p.incarnation)) {
      return std::nullopt;
    }

    std::uint8_t liveness = 0;
    if (!r.u8(liveness) || liveness > static_cast<std::uint8_t>(Liveness::dead)) {
      return std::nullopt;
    }
    p.liveness = static_cast<Liveness>(liveness);

    std::uint16_t addr_len = 0;
    if (!r.u16(addr_len) || addr_len > kMaxAddressLen) {
      return std::nullopt;
    }
    std::span<const std::uint8_t> addr_bytes;
    if (!r.bytes(addr_len, addr_bytes)) {
      return std::nullopt;
    }
    p.address.assign(addr_bytes.begin(), addr_bytes.end());

    peers.push_back(std::move(p));
  }

  if (!r.at_end()) {
    return std::nullopt;  // reject trailing garbage
  }
  return peers;
}

std::optional<ControlType> peek_control_type(std::span<const std::uint8_t> in) {
  if (in.empty()) {
    return std::nullopt;
  }
  switch (in[0]) {
    case static_cast<std::uint8_t>(ControlType::membership):
      return ControlType::membership;
    case static_cast<std::uint8_t>(ControlType::ping):
      return ControlType::ping;
    case static_cast<std::uint8_t>(ControlType::ack):
      return ControlType::ack;
    case static_cast<std::uint8_t>(ControlType::ping_req):
      return ControlType::ping_req;
    case static_cast<std::uint8_t>(ControlType::observed_addr):
      return ControlType::observed_addr;
    default:
      return std::nullopt;
  }
}

std::vector<std::uint8_t> encode_ping(std::uint64_t seq) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::ping));
  put_u64(out, seq);
  return out;
}

std::vector<std::uint8_t> encode_ack(std::uint64_t seq) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::ack));
  put_u64(out, seq);
  return out;
}

std::vector<std::uint8_t> encode_ping_req(std::uint64_t seq,
                                          const PeerId& target) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::ping_req));
  put_u64(out, seq);
  out.insert(out.end(), target.begin(), target.end());
  return out;
}

namespace {

// Decode a bare [type:1][seq:8] body, checking the type tag. Shared by ping/ack.
std::optional<std::uint64_t> decode_seq_message(std::span<const std::uint8_t> in,
                                                ControlType expected) {
  Reader r(in);
  std::uint8_t type = 0;
  if (!r.u8(type) || type != static_cast<std::uint8_t>(expected)) {
    return std::nullopt;
  }
  std::uint64_t seq = 0;
  if (!r.u64(seq) || !r.at_end()) {
    return std::nullopt;
  }
  return seq;
}

}  // namespace

std::optional<PingMessage> decode_ping(std::span<const std::uint8_t> in) {
  const auto seq = decode_seq_message(in, ControlType::ping);
  if (!seq) {
    return std::nullopt;
  }
  return PingMessage{*seq};
}

std::optional<AckMessage> decode_ack(std::span<const std::uint8_t> in) {
  const auto seq = decode_seq_message(in, ControlType::ack);
  if (!seq) {
    return std::nullopt;
  }
  return AckMessage{*seq};
}

std::optional<PingReqMessage> decode_ping_req(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t type = 0;
  if (!r.u8(type) || type != static_cast<std::uint8_t>(ControlType::ping_req)) {
    return std::nullopt;
  }
  PingReqMessage msg;
  if (!r.u64(msg.seq)) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> target_bytes;
  if (!r.bytes(msg.target.size(), target_bytes) || !r.at_end()) {
    return std::nullopt;
  }
  std::copy(target_bytes.begin(), target_bytes.end(), msg.target.begin());
  return msg;
}

std::vector<std::uint8_t> encode_observed_addr(std::string_view address) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::observed_addr));
  const auto len = static_cast<std::uint16_t>(
      address.size() > kMaxAddressLen ? kMaxAddressLen : address.size());
  put_u16(out, len);
  out.insert(out.end(), address.begin(), address.begin() + len);
  return out;
}

std::optional<ObservedAddrMessage> decode_observed_addr(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t type = 0;
  if (!r.u8(type) ||
      type != static_cast<std::uint8_t>(ControlType::observed_addr)) {
    return std::nullopt;
  }
  std::uint16_t addr_len = 0;
  if (!r.u16(addr_len) || addr_len > kMaxAddressLen) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> addr_bytes;
  if (!r.bytes(addr_len, addr_bytes) || !r.at_end()) {
    return std::nullopt;
  }
  ObservedAddrMessage msg;
  msg.address.assign(addr_bytes.begin(), addr_bytes.end());
  return msg;
}

}  // namespace tier::core
