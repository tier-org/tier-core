#include "tier/core/admin.hpp"

#include <algorithm>
#include <cstddef>
#include <tuple>

#include "tier/core/control.hpp"

namespace tier::core {
namespace {

constexpr std::size_t kIdLen = std::tuple_size_v<PeerId>;

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

// A bounds-checked cursor; every read is guarded (see control.cpp for the same
// discipline). Kept local so the admin codec stands on its own.
class Reader {
 public:
  explicit Reader(std::span<const std::uint8_t> in) noexcept : in_(in) {}

  [[nodiscard]] bool u8(std::uint8_t& out) noexcept {
    if (in_.size() - pos_ < 1) {
      return false;
    }
    out = in_[pos_++];
    return true;
  }

  [[nodiscard]] bool u16(std::uint16_t& out) noexcept {
    if (in_.size() - pos_ < 2) {
      return false;
    }
    out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(in_[pos_]) << 8) |
                                     static_cast<std::uint16_t>(in_[pos_ + 1]));
    pos_ += 2;
    return true;
  }

  [[nodiscard]] bool u32(std::uint32_t& out) noexcept {
    if (in_.size() - pos_ < 4) {
      return false;
    }
    out = (static_cast<std::uint32_t>(in_[pos_]) << 24) |
          (static_cast<std::uint32_t>(in_[pos_ + 1]) << 16) |
          (static_cast<std::uint32_t>(in_[pos_ + 2]) << 8) |
          static_cast<std::uint32_t>(in_[pos_ + 3]);
    pos_ += 4;
    return true;
  }

  [[nodiscard]] bool bytes(std::size_t n, std::span<const std::uint8_t>& out) noexcept {
    if (in_.size() - pos_ < n) {
      return false;
    }
    out = in_.subspan(pos_, n);
    pos_ += n;
    return true;
  }

  [[nodiscard]] bool at_end() const noexcept { return pos_ == in_.size(); }

 private:
  std::span<const std::uint8_t> in_;
  std::size_t pos_ = 0;
};

}  // namespace

std::vector<std::uint8_t> encode_admin_request(AdminOp op) {
  return {kAdminVersion, static_cast<std::uint8_t>(op)};
}

std::optional<AdminOp> decode_admin_request(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) || !r.at_end()) {
    return std::nullopt;
  }
  if (op != static_cast<std::uint8_t>(AdminOp::peers)) {
    return std::nullopt;
  }
  return static_cast<AdminOp>(op);
}

std::vector<std::uint8_t> encode_admin_peers(
    const std::vector<PeerInfo>& peers, const std::vector<PeerId>& connected) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::peers));

  const auto membership = encode_membership_message(peers);
  put_u32(out, static_cast<std::uint32_t>(membership.size()));
  out.insert(out.end(), membership.begin(), membership.end());

  const std::size_t count = connected.size() > 0xFFFFU ? 0xFFFFU : connected.size();
  put_u16(out, static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    out.insert(out.end(), connected[i].begin(), connected[i].end());
  }
  return out;
}

std::optional<std::vector<AdminPeer>> decode_admin_peers(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::peers)) {
    return std::nullopt;
  }

  std::uint32_t mlen = 0;
  std::span<const std::uint8_t> mbytes;
  if (!r.u32(mlen) || !r.bytes(mlen, mbytes)) {
    return std::nullopt;
  }
  const auto peers = decode_membership_message(mbytes);
  if (!peers) {
    return std::nullopt;
  }

  std::uint16_t conn_count = 0;
  if (!r.u16(conn_count)) {
    return std::nullopt;
  }
  std::vector<PeerId> connected;
  for (std::uint16_t i = 0; i < conn_count; ++i) {
    std::span<const std::uint8_t> id;
    if (!r.bytes(kIdLen, id)) {
      return std::nullopt;
    }
    PeerId pid{};
    std::copy(id.begin(), id.end(), pid.begin());
    connected.push_back(pid);
  }
  if (!r.at_end()) {
    return std::nullopt;  // trailing bytes
  }

  std::vector<AdminPeer> out;
  out.reserve(peers->size());
  for (const PeerInfo& p : *peers) {
    bool is_connected = false;
    for (const PeerId& c : connected) {
      if (c == p.id) {
        is_connected = true;
        break;
      }
    }
    out.push_back(AdminPeer{p, is_connected});
  }
  return out;
}

}  // namespace tier::core
