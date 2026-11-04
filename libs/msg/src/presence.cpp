#include "tier/msg/presence.hpp"

#include <array>
#include <cstring>
#include <string>

#include "tier/core/control.hpp"
#include "tier/crypto/hash.hpp"

namespace tier::msg {
namespace {

using tier::crypto::Byte;

constexpr char kPresenceTag[] = "tier-presence-v1";

constexpr std::uint8_t kRegisterType =
    static_cast<std::uint8_t>(tier::core::ControlType::presence_register);
constexpr std::uint8_t kLookupType =
    static_cast<std::uint8_t>(tier::core::ControlType::presence_lookup);
constexpr std::uint8_t kResultType =
    static_cast<std::uint8_t>(tier::core::ControlType::presence_result);

void put_tag(std::vector<Byte>& out, const char* tag) {
  const std::size_t n = std::char_traits<char>::length(tag);
  out.insert(out.end(), tag, tag + n);
}

void put_u16(std::vector<Byte>& out, std::uint16_t v) {
  out.push_back(static_cast<Byte>(v >> 8));
  out.push_back(static_cast<Byte>(v & 0xFF));
}

void put_u32(std::vector<Byte>& out, std::uint32_t v) {
  out.push_back(static_cast<Byte>(v >> 24));
  out.push_back(static_cast<Byte>((v >> 16) & 0xFF));
  out.push_back(static_cast<Byte>((v >> 8) & 0xFF));
  out.push_back(static_cast<Byte>(v & 0xFF));
}

void put_u64(std::vector<Byte>& out, std::uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<Byte>((v >> shift) & 0xFF));
  }
}

void put_bytes(std::vector<Byte>& out, ByteSpan b) {
  out.insert(out.end(), b.begin(), b.end());
}

void put_network(std::vector<Byte>& out, std::string_view network) {
  put_u16(out, static_cast<std::uint16_t>(network.size()));
  out.insert(out.end(), network.begin(), network.end());
}

tier::core::PeerId id_of(const tier::crypto::Ed25519PublicKey& pub) {
  const tier::crypto::Digest256 d =
      tier::crypto::sha256(ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId id{};
  std::memcpy(id.data(), d.data(), id.size());
  return id;
}

// Addresses clamped to the shared membership bounds before signing, so a
// decoded record always re-encodes to the same bytes.
std::vector<std::string> clamp_addresses(const std::vector<std::string>& in) {
  std::vector<std::string> out;
  const std::size_t n = in.size() > tier::core::kMaxAddressesPerPeer
                            ? tier::core::kMaxAddressesPerPeer
                            : in.size();
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(in[i].size() > tier::core::kMaxAddressLen
                      ? in[i].substr(0, tier::core::kMaxAddressLen)
                      : in[i]);
  }
  return out;
}

// Append the owner-asserted fields (everything the signature covers, minus the
// domain tag and network prefix): id, identity key, roles, issue stamp, expiry,
// encryption keys, addresses. Shared by the record encoder and the signing
// payload so signed bytes and wire bytes line up exactly.
void append_fields(std::vector<Byte>& out, const PresenceRecord& rec) {
  put_bytes(out, ByteSpan(rec.id.data(), rec.id.size()));
  put_bytes(out, ByteSpan(rec.identity_key.data(), rec.identity_key.size()));
  out.push_back(static_cast<Byte>(rec.roles));
  put_u64(out, rec.issued_unix);
  put_u64(out, rec.expiry_unix);
  put_bytes(out, ByteSpan(rec.enc_keys.x25519.data(), rec.enc_keys.x25519.size()));
  put_bytes(out, ByteSpan(rec.enc_keys.mlkem.data(), rec.enc_keys.mlkem.size()));
  out.push_back(static_cast<Byte>(rec.addresses.size()));
  for (const std::string& a : rec.addresses) {
    put_u16(out, static_cast<std::uint16_t>(a.size()));
    out.insert(out.end(), a.begin(), a.end());
  }
}

std::vector<Byte> build_sig_input(std::string_view network,
                                  const PresenceRecord& rec) {
  std::vector<Byte> m;
  put_tag(m, kPresenceTag);
  put_network(m, network);
  append_fields(m, rec);
  return m;
}

// A minimal bounds-checked reader over untrusted input.
class Reader {
 public:
  explicit Reader(ByteSpan in) : in_(in) {}
  bool take(std::size_t n, ByteSpan& out) {
    if (pos_ > in_.size() || n > in_.size() - pos_) return false;
    out = in_.subspan(pos_, n);
    pos_ += n;
    return true;
  }
  bool take_u8(std::uint8_t& v) {
    ByteSpan s;
    if (!take(1, s)) return false;
    v = s[0];
    return true;
  }
  bool take_u16(std::uint16_t& v) {
    ByteSpan s;
    if (!take(2, s)) return false;
    v = static_cast<std::uint16_t>((s[0] << 8) | s[1]);
    return true;
  }
  bool take_u32(std::uint32_t& v) {
    ByteSpan s;
    if (!take(4, s)) return false;
    v = (static_cast<std::uint32_t>(s[0]) << 24) |
        (static_cast<std::uint32_t>(s[1]) << 16) |
        (static_cast<std::uint32_t>(s[2]) << 8) | static_cast<std::uint32_t>(s[3]);
    return true;
  }
  bool take_u64(std::uint64_t& v) {
    ByteSpan s;
    if (!take(8, s)) return false;
    v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      v = (v << 8) | static_cast<std::uint64_t>(s[i]);
    }
    return true;
  }
  [[nodiscard]] bool done() const { return pos_ == in_.size(); }

 private:
  ByteSpan in_;
  std::size_t pos_ = 0;
};

// Parse and verify a canonical record (the bytes after the control type tag).
// `record` must be consumed exactly. On success record_bytes is set to a copy
// of `record`.
std::optional<PresenceRecord> decode_record(std::string_view network,
                                            ByteSpan record) {
  Reader r(record);
  PresenceRecord rec;

  ByteSpan id;
  ByteSpan key;
  if (!r.take(rec.id.size(), id) || !r.take(rec.identity_key.size(), key)) {
    return std::nullopt;
  }
  std::memcpy(rec.id.data(), id.data(), rec.id.size());
  std::memcpy(rec.identity_key.data(), key.data(), rec.identity_key.size());

  if (!r.take_u8(rec.roles)) return std::nullopt;
  if (!r.take_u64(rec.issued_unix) || !r.take_u64(rec.expiry_unix)) {
    return std::nullopt;
  }

  ByteSpan x;
  ByteSpan k;
  if (!r.take(rec.enc_keys.x25519.size(), x) ||
      !r.take(rec.enc_keys.mlkem.size(), k)) {
    return std::nullopt;
  }
  std::memcpy(rec.enc_keys.x25519.data(), x.data(), rec.enc_keys.x25519.size());
  std::memcpy(rec.enc_keys.mlkem.data(), k.data(), rec.enc_keys.mlkem.size());

  std::uint8_t addr_count = 0;
  if (!r.take_u8(addr_count) || addr_count > tier::core::kMaxAddressesPerPeer) {
    return std::nullopt;
  }
  for (std::uint8_t i = 0; i < addr_count; ++i) {
    std::uint16_t len = 0;
    ByteSpan a;
    if (!r.take_u16(len) || len > tier::core::kMaxAddressLen ||
        !r.take(len, a)) {
      return std::nullopt;
    }
    rec.addresses.emplace_back(reinterpret_cast<const char*>(a.data()), a.size());
  }

  std::uint8_t sig_len = 0;
  ByteSpan sig;
  if (!r.take_u8(sig_len) || sig_len > tier::core::kMaxSignatureLen ||
      !r.take(sig_len, sig) || !r.done()) {
    return std::nullopt;
  }

  // The claimed id must hash to the carried identity key, and the signature
  // must verify under it. (The record is relayed, so the key travels with it.)
  if (id_of(rec.identity_key) != rec.id) return std::nullopt;
  const std::vector<Byte> sig_input = build_sig_input(network, rec);
  tier::crypto::Ed25519Verifier v(rec.identity_key);
  if (!v.verify(ByteSpan(sig_input.data(), sig_input.size()), sig)) {
    return std::nullopt;
  }

  rec.record_bytes.assign(record.begin(), record.end());
  return rec;
}

}  // namespace

std::vector<Byte> make_presence_register(const tier::crypto::NodeIdentity& self,
                                         std::string_view network,
                                         tier::core::RoleSet roles,
                                         const std::vector<std::string>& addresses,
                                         std::uint64_t issued_unix,
                                         std::uint64_t expiry_unix) {
  PresenceRecord rec;
  rec.id = id_of(self.public_key());
  rec.identity_key = self.public_key();
  rec.roles = roles;
  rec.issued_unix = issued_unix;
  rec.expiry_unix = expiry_unix;
  const auto x = self.x25519_identity_key();
  const auto k = self.mlkem768_identity_key();
  rec.enc_keys.x25519 = x.public_key;
  rec.enc_keys.mlkem = k.public_key;
  rec.addresses = clamp_addresses(addresses);

  const std::vector<Byte> sig_input = build_sig_input(network, rec);
  const std::vector<Byte> sig =
      self.signer().sign(ByteSpan(sig_input.data(), sig_input.size()));

  std::vector<Byte> record;
  append_fields(record, rec);
  record.push_back(static_cast<Byte>(sig.size()));
  put_bytes(record, ByteSpan(sig.data(), sig.size()));

  std::vector<Byte> out;
  out.push_back(kRegisterType);
  put_bytes(out, ByteSpan(record.data(), record.size()));
  return out;
}

std::optional<PresenceRecord> open_presence_register(std::string_view network,
                                                     ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kRegisterType) return std::nullopt;
  ByteSpan record;
  if (!r.take(message.size() - 1, record)) return std::nullopt;
  return decode_record(network, record);
}

std::vector<Byte> make_presence_lookup(const tier::core::PeerId& target) {
  std::vector<Byte> out;
  out.push_back(kLookupType);
  put_bytes(out, ByteSpan(target.data(), target.size()));
  return out;
}

std::optional<tier::core::PeerId> open_presence_lookup(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kLookupType) return std::nullopt;
  tier::core::PeerId target{};
  ByteSpan t;
  if (!r.take(target.size(), t) || !r.done()) return std::nullopt;
  std::memcpy(target.data(), t.data(), target.size());
  return target;
}

std::vector<Byte> make_presence_result(const tier::core::PeerId& queried,
                                       ByteSpan record_bytes) {
  std::vector<Byte> out;
  out.push_back(kResultType);
  put_bytes(out, ByteSpan(queried.data(), queried.size()));
  if (record_bytes.empty()) {
    out.push_back(0);  // not found
    return out;
  }
  out.push_back(1);  // found
  put_u32(out, static_cast<std::uint32_t>(record_bytes.size()));
  put_bytes(out, record_bytes);
  return out;
}

std::optional<std::optional<PresenceRecord>> open_presence_result(
    std::string_view network, const tier::core::PeerId& expected,
    ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kResultType) return std::nullopt;

  tier::core::PeerId queried{};
  ByteSpan q;
  if (!r.take(queried.size(), q)) return std::nullopt;
  std::memcpy(queried.data(), q.data(), queried.size());
  if (queried != expected) return std::nullopt;

  std::uint8_t found = 0;
  if (!r.take_u8(found)) return std::nullopt;
  if (found == 0) {
    if (!r.done()) return std::nullopt;
    return std::optional<PresenceRecord>{};  // verified not-found
  }
  if (found != 1) return std::nullopt;

  std::uint32_t len = 0;
  ByteSpan record;
  if (!r.take_u32(len) || !r.take(len, record) || !r.done()) return std::nullopt;

  auto rec = decode_record(network, record);
  if (!rec || rec->id != expected) return std::nullopt;
  // Wrap the (present) inner optional without dereferencing it.
  return std::optional<std::optional<PresenceRecord>>{std::move(rec)};
}

}  // namespace tier::msg
