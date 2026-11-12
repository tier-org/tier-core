#include "tier/core/control.hpp"

#include <algorithm>
#include <cstddef>
#include <string_view>
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

// How many addresses of this peer are put on the wire (clamped to the bound).
std::size_t wire_addr_count(const PeerInfo& p) noexcept {
  return p.addresses.size() > kMaxAddressesPerPeer ? kMaxAddressesPerPeer
                                                   : p.addresses.size();
}

// Append the owner-asserted fields (everything but liveness) that the signature
// covers. Shared by the wire encoder and the signing-payload builder so the
// bytes an owner signs are exactly the bytes a verifier reconstructs.
void append_owner_fields(std::vector<std::uint8_t>& out, const PeerInfo& p) {
  out.insert(out.end(), p.id.begin(), p.id.end());
  out.insert(out.end(), p.public_key.begin(), p.public_key.end());
  out.push_back(static_cast<std::uint8_t>(p.roles));
  put_u64(out, p.incarnation);
  const std::size_t addr_count = wire_addr_count(p);
  out.push_back(static_cast<std::uint8_t>(addr_count));
  for (std::size_t a = 0; a < addr_count; ++a) {
    const std::string& addr = p.addresses[a];
    const auto addr_len = static_cast<std::uint16_t>(
        addr.size() > kMaxAddressLen ? kMaxAddressLen : addr.size());
    put_u16(out, addr_len);
    out.insert(out.end(), addr.begin(), addr.begin() + addr_len);
  }
  const auto ver_len = static_cast<std::uint8_t>(
      p.version.size() > kMaxVersionLen ? kMaxVersionLen : p.version.size());
  out.push_back(ver_len);
  out.insert(out.end(), p.version.begin(), p.version.begin() + ver_len);
}

// Append one peer's full wire record: id, public key, signature, then the
// owner-asserted fields with the liveness byte spliced in after the id/key/sig.
void append_peer(std::vector<std::uint8_t>& out, const PeerInfo& p) {
  out.insert(out.end(), p.id.begin(), p.id.end());
  out.insert(out.end(), p.public_key.begin(), p.public_key.end());
  const auto sig_len = static_cast<std::uint8_t>(
      p.signature.size() > kMaxSignatureLen ? kMaxSignatureLen
                                            : p.signature.size());
  out.push_back(sig_len);
  out.insert(out.end(), p.signature.begin(), p.signature.begin() + sig_len);
  out.push_back(static_cast<std::uint8_t>(p.roles));
  put_u64(out, p.incarnation);
  out.push_back(static_cast<std::uint8_t>(p.liveness));
  const std::size_t addr_count = wire_addr_count(p);
  out.push_back(static_cast<std::uint8_t>(addr_count));
  for (std::size_t a = 0; a < addr_count; ++a) {
    const std::string& addr = p.addresses[a];
    const auto addr_len = static_cast<std::uint16_t>(
        addr.size() > kMaxAddressLen ? kMaxAddressLen : addr.size());
    put_u16(out, addr_len);
    out.insert(out.end(), addr.begin(), addr.begin() + addr_len);
  }
  const auto ver_len = static_cast<std::uint8_t>(
      p.version.size() > kMaxVersionLen ? kMaxVersionLen : p.version.size());
  out.push_back(ver_len);
  out.insert(out.end(), p.version.begin(), p.version.begin() + ver_len);
}

// Exact number of wire bytes append_peer would emit for this peer.
std::size_t peer_wire_size(const PeerInfo& p) noexcept {
  const std::size_t sig_len =
      p.signature.size() > kMaxSignatureLen ? kMaxSignatureLen
                                            : p.signature.size();
  std::size_t n = p.id.size() + p.public_key.size() + 1 /*sig_len*/ + sig_len +
                  1 /*role*/ + 8 /*incarnation*/ + 1 /*liveness*/ +
                  1 /*addr_count*/;
  const std::size_t addr_count = wire_addr_count(p);
  for (std::size_t a = 0; a < addr_count; ++a) {
    n += 2 + (p.addresses[a].size() > kMaxAddressLen ? kMaxAddressLen
                                                     : p.addresses[a].size());
  }
  n += 1 /*ver_len*/ +
       (p.version.size() > kMaxVersionLen ? kMaxVersionLen : p.version.size());
  return n;
}

// The 5-byte fixed header of a membership message: type(1) + count(4).
inline constexpr std::size_t kMembershipHeaderBytes = 5;

}  // namespace

std::vector<std::uint8_t> encode_membership_message(
    const std::vector<PeerInfo>& peers) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(ControlType::membership));
  put_u32(out, static_cast<std::uint32_t>(peers.size()));
  for (const PeerInfo& p : peers) {
    append_peer(out, p);
  }
  return out;
}

std::vector<std::vector<std::uint8_t>> encode_membership_messages(
    const std::vector<PeerInfo>& peers, std::size_t max_bytes) {
  std::vector<std::vector<std::uint8_t>> messages;
  std::vector<PeerInfo> batch;
  std::size_t batch_bytes = kMembershipHeaderBytes;
  for (const PeerInfo& p : peers) {
    const std::size_t sz = peer_wire_size(p);
    // Flush the current batch before it would exceed the budget, but never emit
    // an empty message: a single peer larger than the budget (should not happen,
    // a peer is far smaller than a frame) still goes out on its own.
    if (!batch.empty() && batch_bytes + sz > max_bytes) {
      messages.push_back(encode_membership_message(batch));
      batch.clear();
      batch_bytes = kMembershipHeaderBytes;
    }
    batch.push_back(p);
    batch_bytes += sz;
  }
  if (!batch.empty() || peers.empty()) {
    messages.push_back(encode_membership_message(batch));
  }
  return messages;
}

std::vector<std::uint8_t> membership_signing_payload(std::string_view network,
                                                     const PeerInfo& peer) {
  // Domain-separation tag: binds the signature to this exact purpose so it can
  // never be mistaken for a signature over anything else. Versioned for a future
  // format change.
  static constexpr std::string_view kTag = "tier-membership-v1";
  std::vector<std::uint8_t> out;
  out.insert(out.end(), kTag.begin(), kTag.end());
  out.push_back(0x00);  // separator between the tag and the network name
  put_u16(out, static_cast<std::uint16_t>(network.size() > 0xFFFFU
                                              ? 0xFFFFU
                                              : network.size()));
  out.insert(out.end(), network.begin(), network.end());
  append_owner_fields(out, peer);
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

    std::span<const std::uint8_t> pubkey_bytes;
    if (!r.bytes(p.public_key.size(), pubkey_bytes)) {
      return std::nullopt;
    }
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), p.public_key.begin());

    std::uint8_t sig_len = 0;
    if (!r.u8(sig_len) || sig_len > kMaxSignatureLen) {
      return std::nullopt;
    }
    std::span<const std::uint8_t> sig_bytes;
    if (!r.bytes(sig_len, sig_bytes)) {
      return std::nullopt;
    }
    p.signature.assign(sig_bytes.begin(), sig_bytes.end());

    std::uint8_t roles = 0;
    // Accept the roles byte verbatim, including bits this version does not
    // define. Unknown bits are inert here (is_infrastructure / has_role only
    // test known bits) but must be preserved: the byte is covered by the owner
    // signature, so stripping it would break verification when the record is
    // re-gossiped, and keeping it lets a newer role propagate through older
    // nodes untouched. Forward compatibility - new roles never break the wire.
    if (!r.u8(roles)) {
      return std::nullopt;
    }
    p.roles = roles;

    if (!r.u64(p.incarnation)) {
      return std::nullopt;
    }

    std::uint8_t liveness = 0;
    if (!r.u8(liveness) || liveness > static_cast<std::uint8_t>(Liveness::dead)) {
      return std::nullopt;
    }
    p.liveness = static_cast<Liveness>(liveness);

    std::uint8_t addr_count = 0;
    if (!r.u8(addr_count) || addr_count > kMaxAddressesPerPeer) {
      return std::nullopt;
    }
    p.addresses.reserve(addr_count);
    for (std::uint8_t a = 0; a < addr_count; ++a) {
      std::uint16_t addr_len = 0;
      if (!r.u16(addr_len) || addr_len > kMaxAddressLen) {
        return std::nullopt;
      }
      std::span<const std::uint8_t> addr_bytes;
      if (!r.bytes(addr_len, addr_bytes)) {
        return std::nullopt;
      }
      p.addresses.emplace_back(addr_bytes.begin(), addr_bytes.end());
    }

    std::uint8_t ver_len = 0;
    if (!r.u8(ver_len) || ver_len > kMaxVersionLen) {
      return std::nullopt;
    }
    std::span<const std::uint8_t> ver_bytes;
    if (!r.bytes(ver_len, ver_bytes)) {
      return std::nullopt;
    }
    // The version is rendered by diagnostics tools; reject control characters
    // so a hostile peer cannot smuggle terminal escapes through it. Printable
    // ASCII only (space through '~').
    for (const std::uint8_t b : ver_bytes) {
      if (b < 0x20 || b > 0x7E) {
        return std::nullopt;
      }
    }
    p.version.assign(ver_bytes.begin(), ver_bytes.end());

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
    case static_cast<std::uint8_t>(ControlType::enc_keys):
      return ControlType::enc_keys;
    case static_cast<std::uint8_t>(ControlType::app_sealed):
      return ControlType::app_sealed;
    case static_cast<std::uint8_t>(ControlType::presence_register):
      return ControlType::presence_register;
    case static_cast<std::uint8_t>(ControlType::presence_lookup):
      return ControlType::presence_lookup;
    case static_cast<std::uint8_t>(ControlType::presence_result):
      return ControlType::presence_result;
    case static_cast<std::uint8_t>(ControlType::user_register):
      return ControlType::user_register;
    case static_cast<std::uint8_t>(ControlType::user_deregister):
      return ControlType::user_deregister;
    case static_cast<std::uint8_t>(ControlType::user_lookup):
      return ControlType::user_lookup;
    case static_cast<std::uint8_t>(ControlType::user_result):
      return ControlType::user_result;
    case static_cast<std::uint8_t>(ControlType::hole_punch_request):
      return ControlType::hole_punch_request;
    case static_cast<std::uint8_t>(ControlType::hole_punch_signal):
      return ControlType::hole_punch_signal;
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
