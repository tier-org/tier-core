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

std::vector<std::uint8_t> encode_admin_send(const PeerId& recipient,
                                            std::uint8_t suite,
                                            std::span<const std::uint8_t> plaintext) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::send));
  out.insert(out.end(), recipient.begin(), recipient.end());
  out.push_back(suite);
  put_u32(out, static_cast<std::uint32_t>(plaintext.size()));
  out.insert(out.end(), plaintext.begin(), plaintext.end());
  return out;
}

std::vector<std::uint8_t> encode_admin_send_as(const PeerId& from_user,
                                               const PeerId& to_user,
                                               std::uint8_t suite,
                                               std::span<const std::uint8_t> plaintext) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::send_as));
  out.insert(out.end(), from_user.begin(), from_user.end());
  out.insert(out.end(), to_user.begin(), to_user.end());
  out.push_back(suite);
  put_u32(out, static_cast<std::uint32_t>(plaintext.size()));
  out.insert(out.end(), plaintext.begin(), plaintext.end());
  return out;
}

std::vector<std::uint8_t> encode_admin_user_add(
    std::optional<std::array<std::uint8_t, 32>> seed) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::user_add));
  out.push_back(seed ? 1 : 0);
  if (seed) {
    out.insert(out.end(), seed->begin(), seed->end());
  }
  return out;
}

std::vector<std::uint8_t> encode_admin_user_remove(const PeerId& user_id) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::user_remove));
  out.insert(out.end(), user_id.begin(), user_id.end());
  return out;
}

std::vector<std::uint8_t> encode_admin_subscribe(const PeerId& user_id) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::subscribe));
  out.insert(out.end(), user_id.begin(), user_id.end());
  return out;
}

std::optional<AdminRequest> decode_admin_request(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op)) {
    return std::nullopt;
  }
  AdminRequest req;
  switch (static_cast<AdminOp>(op)) {
    case AdminOp::peers:
    case AdminOp::inbox:
    case AdminOp::id:
    case AdminOp::user_list:
      if (!r.at_end()) {
        return std::nullopt;
      }
      req.op = static_cast<AdminOp>(op);
      return req;
    case AdminOp::send: {
      // A 32-byte device id, a suite byte, and a length-prefixed plaintext.
      std::span<const std::uint8_t> id;
      std::uint8_t suite = 0;
      std::uint32_t len = 0;
      if (!r.bytes(kIdLen, id) || !r.u8(suite) || !r.u32(len)) {
        return std::nullopt;
      }
      if (len > kMaxAdminMessageBytes) {
        return std::nullopt;
      }
      std::span<const std::uint8_t> body;
      if (!r.bytes(len, body) || !r.at_end()) {
        return std::nullopt;
      }
      req.op = static_cast<AdminOp>(op);
      std::copy(id.begin(), id.end(), req.recipient.begin());
      req.suite = suite;
      req.plaintext.assign(body.begin(), body.end());
      return req;
    }
    case AdminOp::send_as: {
      // A from-user id, a to-user id, a suite byte, and a length-prefixed body.
      std::span<const std::uint8_t> from;
      std::span<const std::uint8_t> to;
      std::uint8_t suite = 0;
      std::uint32_t len = 0;
      if (!r.bytes(kIdLen, from) || !r.bytes(kIdLen, to) || !r.u8(suite) ||
          !r.u32(len)) {
        return std::nullopt;
      }
      if (len > kMaxAdminMessageBytes) {
        return std::nullopt;
      }
      std::span<const std::uint8_t> body;
      if (!r.bytes(len, body) || !r.at_end()) {
        return std::nullopt;
      }
      req.op = static_cast<AdminOp>(op);
      std::copy(from.begin(), from.end(), req.from_user.begin());
      std::copy(to.begin(), to.end(), req.recipient.begin());
      req.suite = suite;
      req.plaintext.assign(body.begin(), body.end());
      return req;
    }
    case AdminOp::user_add: {
      std::uint8_t has_seed = 0;
      if (!r.u8(has_seed) || has_seed > 1) {
        return std::nullopt;
      }
      req.op = AdminOp::user_add;
      if (has_seed == 1) {
        std::span<const std::uint8_t> seed;
        if (!r.bytes(req.seed.size(), seed)) {
          return std::nullopt;
        }
        req.has_seed = true;
        std::copy(seed.begin(), seed.end(), req.seed.begin());
      }
      if (!r.at_end()) {
        return std::nullopt;
      }
      return req;
    }
    case AdminOp::user_remove: {
      std::span<const std::uint8_t> id;
      if (!r.bytes(kIdLen, id) || !r.at_end()) {
        return std::nullopt;
      }
      req.op = AdminOp::user_remove;
      std::copy(id.begin(), id.end(), req.recipient.begin());
      return req;
    }
    case AdminOp::subscribe: {
      std::span<const std::uint8_t> id;
      if (!r.bytes(kIdLen, id) || !r.at_end()) {
        return std::nullopt;
      }
      req.op = AdminOp::subscribe;
      std::copy(id.begin(), id.end(), req.recipient.begin());
      return req;
    }
  }
  return std::nullopt;  // unknown op
}

std::vector<std::uint8_t> encode_admin_send_reply(bool ok) {
  return {kAdminVersion, static_cast<std::uint8_t>(AdminOp::send),
          static_cast<std::uint8_t>(ok ? 0 : 1)};
}

std::optional<bool> decode_admin_send_reply(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint8_t status = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::send) || !r.u8(status) ||
      !r.at_end()) {
    return std::nullopt;
  }
  return status == 0;
}

std::vector<std::uint8_t> encode_admin_send_as_reply(bool ok) {
  return {kAdminVersion, static_cast<std::uint8_t>(AdminOp::send_as),
          static_cast<std::uint8_t>(ok ? 0 : 1)};
}

std::optional<bool> decode_admin_send_as_reply(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint8_t status = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::send_as) || !r.u8(status) ||
      !r.at_end()) {
    return std::nullopt;
  }
  return status == 0;
}

std::vector<std::uint8_t> encode_admin_user_add_reply(const AdminUserAddReply& rep) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::user_add));
  out.push_back(static_cast<std::uint8_t>(rep.ok ? 0 : 1));
  out.insert(out.end(), rep.user_id.begin(), rep.user_id.end());
  return out;
}

std::optional<AdminUserAddReply> decode_admin_user_add_reply(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint8_t status = 0;
  std::span<const std::uint8_t> uid;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::user_add) || !r.u8(status) ||
      !r.bytes(kIdLen, uid) || !r.at_end()) {
    return std::nullopt;
  }
  AdminUserAddReply out;
  out.ok = status == 0;
  std::copy(uid.begin(), uid.end(), out.user_id.begin());
  return out;
}

std::vector<std::uint8_t> encode_admin_user_remove_reply(bool existed) {
  return {kAdminVersion, static_cast<std::uint8_t>(AdminOp::user_remove),
          static_cast<std::uint8_t>(existed ? 1 : 0)};
}

std::optional<bool> decode_admin_user_remove_reply(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint8_t existed = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::user_remove) || !r.u8(existed) ||
      existed > 1 || !r.at_end()) {
    return std::nullopt;
  }
  return existed == 1;
}

std::vector<std::uint8_t> encode_admin_user_list(const std::vector<PeerId>& users) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::user_list));
  const std::size_t count = users.size() > 0xFFFFU ? 0xFFFFU : users.size();
  put_u16(out, static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    out.insert(out.end(), users[i].begin(), users[i].end());
  }
  return out;
}

std::optional<std::vector<PeerId>> decode_admin_user_list(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint16_t count = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::user_list) || !r.u16(count)) {
    return std::nullopt;
  }
  std::vector<PeerId> out;
  for (std::uint16_t i = 0; i < count; ++i) {
    std::span<const std::uint8_t> id;
    if (!r.bytes(kIdLen, id)) {
      return std::nullopt;
    }
    PeerId u{};
    std::copy(id.begin(), id.end(), u.begin());
    out.push_back(u);
  }
  if (!r.at_end()) {
    return std::nullopt;
  }
  return out;
}

std::vector<std::uint8_t> encode_admin_id_reply(const AdminId& id) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::id));
  out.insert(out.end(), id.device_id.begin(), id.device_id.end());
  return out;
}

std::optional<AdminId> decode_admin_id_reply(std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::span<const std::uint8_t> dev;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::id) || !r.bytes(kIdLen, dev) ||
      !r.at_end()) {
    return std::nullopt;
  }
  AdminId out;
  std::copy(dev.begin(), dev.end(), out.device_id.begin());
  return out;
}

std::vector<std::uint8_t> encode_admin_inbox(
    const std::vector<AdminInboxMessage>& messages) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::inbox));
  const std::size_t count = messages.size() > 0xFFFFU ? 0xFFFFU : messages.size();
  put_u16(out, static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    const AdminInboxMessage& m = messages[i];
    out.insert(out.end(), m.sender.begin(), m.sender.end());
    out.push_back(m.sender_user ? 1 : 0);
    if (m.sender_user) {
      out.insert(out.end(), m.sender_user->begin(), m.sender_user->end());
    }
    out.push_back(m.recipient_user ? 1 : 0);
    if (m.recipient_user) {
      out.insert(out.end(), m.recipient_user->begin(), m.recipient_user->end());
    }
    out.push_back(m.suite);
    put_u32(out, static_cast<std::uint32_t>(m.plaintext.size()));
    out.insert(out.end(), m.plaintext.begin(), m.plaintext.end());
  }
  return out;
}

std::optional<std::vector<AdminInboxMessage>> decode_admin_inbox(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  std::uint16_t count = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::inbox) || !r.u16(count)) {
    return std::nullopt;
  }
  std::vector<AdminInboxMessage> out;
  for (std::uint16_t i = 0; i < count; ++i) {
    std::span<const std::uint8_t> sender;
    std::uint8_t has_user = 0;
    if (!r.bytes(kIdLen, sender) || !r.u8(has_user)) {
      return std::nullopt;
    }
    AdminInboxMessage m;
    std::copy(sender.begin(), sender.end(), m.sender.begin());
    if (has_user == 1) {
      std::span<const std::uint8_t> uid;
      if (!r.bytes(kIdLen, uid)) {
        return std::nullopt;
      }
      PeerId u{};
      std::copy(uid.begin(), uid.end(), u.begin());
      m.sender_user = u;
    } else if (has_user != 0) {
      return std::nullopt;
    }
    std::uint8_t has_rcpt = 0;
    if (!r.u8(has_rcpt)) {
      return std::nullopt;
    }
    if (has_rcpt == 1) {
      std::span<const std::uint8_t> rid;
      if (!r.bytes(kIdLen, rid)) {
        return std::nullopt;
      }
      PeerId u{};
      std::copy(rid.begin(), rid.end(), u.begin());
      m.recipient_user = u;
    } else if (has_rcpt != 0) {
      return std::nullopt;
    }
    std::uint8_t suite = 0;
    std::uint32_t len = 0;
    if (!r.u8(suite) || !r.u32(len)) {
      return std::nullopt;
    }
    std::span<const std::uint8_t> body;
    if (!r.bytes(len, body)) {
      return std::nullopt;
    }
    m.suite = suite;
    m.plaintext.assign(body.begin(), body.end());
    out.push_back(std::move(m));
  }
  if (!r.at_end()) {
    return std::nullopt;
  }
  return out;
}

std::vector<std::uint8_t> encode_admin_stream_message(const AdminStreamMessage& m) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminStreamKind::message));
  out.insert(out.end(), m.sender_user.begin(), m.sender_user.end());
  out.push_back(m.suite);
  put_u16(out, m.type);
  out.insert(out.end(), m.msg_id.begin(), m.msg_id.end());
  put_u32(out, static_cast<std::uint32_t>(m.payload.size()));
  out.insert(out.end(), m.payload.begin(), m.payload.end());
  return out;
}

std::vector<std::uint8_t> encode_admin_stream_receipt(const AdminStreamReceipt& rr) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminStreamKind::receipt));
  out.insert(out.end(), rr.msg_id.begin(), rr.msg_id.end());
  return out;
}

std::optional<AdminStreamEvent> decode_admin_stream_event(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t kind = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(kind)) {
    return std::nullopt;
  }
  AdminStreamEvent ev;
  switch (static_cast<AdminStreamKind>(kind)) {
    case AdminStreamKind::message: {
      std::span<const std::uint8_t> su;
      std::uint8_t suite = 0;
      std::uint16_t type = 0;
      std::span<const std::uint8_t> mid;
      std::uint32_t len = 0;
      if (!r.bytes(kIdLen, su) || !r.u8(suite) || !r.u16(type) ||
          !r.bytes(ev.message.msg_id.size(), mid) || !r.u32(len)) {
        return std::nullopt;
      }
      if (len > kMaxAdminMessageBytes) {
        return std::nullopt;
      }
      std::span<const std::uint8_t> body;
      if (!r.bytes(len, body) || !r.at_end()) {
        return std::nullopt;
      }
      ev.kind = AdminStreamKind::message;
      std::copy(su.begin(), su.end(), ev.message.sender_user.begin());
      ev.message.suite = suite;
      ev.message.type = type;
      std::copy(mid.begin(), mid.end(), ev.message.msg_id.begin());
      ev.message.payload.assign(body.begin(), body.end());
      return ev;
    }
    case AdminStreamKind::receipt: {
      std::span<const std::uint8_t> mid;
      if (!r.bytes(ev.receipt.msg_id.size(), mid) || !r.at_end()) {
        return std::nullopt;
      }
      ev.kind = AdminStreamKind::receipt;
      std::copy(mid.begin(), mid.end(), ev.receipt.msg_id.begin());
      return ev;
    }
  }
  return std::nullopt;  // unknown kind
}

std::vector<std::uint8_t> encode_admin_peers(
    std::string_view network, const std::vector<PeerInfo>& peers,
    const std::vector<PeerId>& connected) {
  std::vector<std::uint8_t> out;
  out.push_back(kAdminVersion);
  out.push_back(static_cast<std::uint8_t>(AdminOp::peers));

  // The daemon's own network. A valid network name is at most 32 bytes, so a
  // single length byte is ample; truncate defensively rather than overflow it.
  const std::size_t net_len = network.size() > 0xFFU ? 0xFFU : network.size();
  out.push_back(static_cast<std::uint8_t>(net_len));
  out.insert(out.end(), network.begin(), network.begin() + net_len);

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

std::optional<AdminPeersReply> decode_admin_peers(
    std::span<const std::uint8_t> in) {
  Reader r(in);
  std::uint8_t ver = 0;
  std::uint8_t op = 0;
  if (!r.u8(ver) || ver != kAdminVersion || !r.u8(op) ||
      op != static_cast<std::uint8_t>(AdminOp::peers)) {
    return std::nullopt;
  }

  std::uint8_t net_len = 0;
  std::span<const std::uint8_t> net_bytes;
  if (!r.u8(net_len) || !r.bytes(net_len, net_bytes)) {
    return std::nullopt;
  }
  std::string network(net_bytes.begin(), net_bytes.end());

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

  AdminPeersReply reply;
  reply.network = std::move(network);
  reply.peers.reserve(peers->size());
  for (const PeerInfo& p : *peers) {
    bool is_connected = false;
    for (const PeerId& c : connected) {
      if (c == p.id) {
        is_connected = true;
        break;
      }
    }
    reply.peers.push_back(AdminPeer{p, is_connected});
  }
  return reply;
}

}  // namespace tier::core
