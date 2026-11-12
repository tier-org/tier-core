#include "tier/msg/user.hpp"

#include <cstring>
#include <string>

#include "tier/core/control.hpp"
#include "tier/crypto/hash.hpp"

namespace tier::msg {
namespace {

using tier::crypto::Byte;

constexpr char kCredTag[] = "tier-user-cred-v1";

constexpr std::uint8_t kUserRegisterType =
    static_cast<std::uint8_t>(tier::core::ControlType::user_register);
constexpr std::uint8_t kUserLookupType =
    static_cast<std::uint8_t>(tier::core::ControlType::user_lookup);
constexpr std::uint8_t kUserResultType =
    static_cast<std::uint8_t>(tier::core::ControlType::user_result);
constexpr std::uint8_t kUserDeregisterType =
    static_cast<std::uint8_t>(tier::core::ControlType::user_deregister);

// Bounds for the directory codecs (untrusted input).
constexpr std::uint16_t kMaxCredBlob = 256;    // expiry+siglen+sig, ~138 bytes
constexpr std::uint16_t kMaxDevicesPerUser = 64;

void put_tag(std::vector<Byte>& out, const char* tag) {
  const std::size_t n = std::char_traits<char>::length(tag);
  out.insert(out.end(), tag, tag + n);
}

void put_u16(std::vector<Byte>& out, std::uint16_t v) {
  out.push_back(static_cast<Byte>(v >> 8));
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

// The message the user key signs to authorize a device.
std::vector<Byte> credential_signed_input(std::string_view network,
                                          const tier::crypto::Ed25519PublicKey& user_pub,
                                          const tier::core::PeerId& device_id,
                                          std::uint64_t expiry_unix) {
  std::vector<Byte> m;
  put_tag(m, kCredTag);
  put_network(m, network);
  put_bytes(m, ByteSpan(user_pub.data(), user_pub.size()));
  put_bytes(m, ByteSpan(device_id.data(), device_id.size()));
  put_u64(m, expiry_unix);
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
  bool take_u64(std::uint64_t& v) {
    ByteSpan s;
    if (!take(8, s)) return false;
    v = 0;
    for (std::size_t i = 0; i < 8; ++i) v = (v << 8) | static_cast<std::uint64_t>(s[i]);
    return true;
  }
  ByteSpan rest() { return in_.subspan(pos_); }

 private:
  ByteSpan in_;
  std::size_t pos_ = 0;
};

tier::core::PeerId id_of(const tier::crypto::Ed25519PublicKey& pub) {
  const tier::crypto::Digest256 d =
      tier::crypto::sha256(ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId id{};
  std::memcpy(id.data(), d.data(), id.size());
  return id;
}

// Credential blob layout: [expiry:8][sig_len:2][sig].
constexpr std::size_t kMaxCredSig = 128;

}  // namespace

tier::core::PeerId user_id_of(const tier::crypto::Ed25519PublicKey& user_pub) {
  return id_of(user_pub);
}

std::vector<Byte> make_device_credential(const tier::crypto::NodeIdentity& user,
                                         std::string_view network,
                                         const tier::core::PeerId& device_id,
                                         std::uint64_t expiry_unix) {
  const std::vector<Byte> input =
      credential_signed_input(network, user.public_key(), device_id, expiry_unix);
  const std::vector<Byte> sig =
      user.signer().sign(ByteSpan(input.data(), input.size()));

  std::vector<Byte> out;
  put_u64(out, expiry_unix);
  put_u16(out, static_cast<std::uint16_t>(sig.size()));
  put_bytes(out, ByteSpan(sig.data(), sig.size()));
  return out;
}

bool verify_device_credential(std::string_view network,
                              const tier::crypto::Ed25519PublicKey& user_pub,
                              const tier::core::PeerId& device_id,
                              std::uint64_t now_unix, ByteSpan credential) {
  Reader r(credential);
  std::uint64_t expiry = 0;
  std::uint16_t sig_len = 0;
  ByteSpan sig;
  if (!r.take_u64(expiry) || !r.take_u16(sig_len) || sig_len > kMaxCredSig ||
      !r.take(sig_len, sig)) {
    return false;
  }
  if (!r.rest().empty()) return false;  // trailing bytes
  if (now_unix >= expiry) return false;  // expired

  const std::vector<Byte> input =
      credential_signed_input(network, user_pub, device_id, expiry);
  tier::crypto::Ed25519Verifier v(user_pub);
  return v.verify(ByteSpan(input.data(), input.size()), sig);
}

std::vector<Byte> make_user_envelope(const tier::crypto::Ed25519PublicKey& sender_user_pub,
                                     ByteSpan credential,
                                     const tier::core::PeerId& recipient_user_id,
                                     ByteSpan inner_plaintext) {
  std::vector<Byte> out;
  put_bytes(out, ByteSpan(sender_user_pub.data(), sender_user_pub.size()));
  put_u16(out, static_cast<std::uint16_t>(credential.size()));
  put_bytes(out, credential);
  put_bytes(out, ByteSpan(recipient_user_id.data(), recipient_user_id.size()));
  put_bytes(out, inner_plaintext);
  return out;
}

std::optional<OpenedUser> open_user_envelope(std::string_view network,
                                             const tier::core::PeerId& sender_device,
                                             std::uint64_t now_unix,
                                             ByteSpan envelope) {
  Reader r(envelope);
  tier::crypto::Ed25519PublicKey user_pub{};
  ByteSpan pub;
  if (!r.take(user_pub.size(), pub)) return std::nullopt;
  std::memcpy(user_pub.data(), pub.data(), user_pub.size());

  std::uint16_t cred_len = 0;
  ByteSpan cred;
  if (!r.take_u16(cred_len) || !r.take(cred_len, cred)) return std::nullopt;

  if (!verify_device_credential(network, user_pub, sender_device, now_unix, cred)) {
    return std::nullopt;
  }

  tier::core::PeerId recipient{};
  ByteSpan rcpt;
  if (!r.take(recipient.size(), rcpt)) return std::nullopt;
  std::memcpy(recipient.data(), rcpt.data(), recipient.size());

  const ByteSpan inner = r.rest();
  OpenedUser out;
  out.sender_user_id = id_of(user_pub);
  out.recipient_user_id = recipient;
  out.plaintext.assign(inner.begin(), inner.end());
  return out;
}

std::vector<Byte> make_user_register(const tier::crypto::Ed25519PublicKey& user_pub,
                                     ByteSpan credential, std::uint64_t issued_unix,
                                     std::uint64_t expiry_unix) {
  std::vector<Byte> out;
  out.push_back(kUserRegisterType);
  put_bytes(out, ByteSpan(user_pub.data(), user_pub.size()));
  put_u64(out, issued_unix);
  put_u64(out, expiry_unix);
  put_u16(out, static_cast<std::uint16_t>(credential.size()));
  put_bytes(out, credential);
  return out;
}

std::optional<UserRegister> open_user_register(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kUserRegisterType) return std::nullopt;

  UserRegister reg;
  ByteSpan pub;
  if (!r.take(reg.user_pub.size(), pub)) return std::nullopt;
  std::memcpy(reg.user_pub.data(), pub.data(), reg.user_pub.size());
  if (!r.take_u64(reg.issued_unix) || !r.take_u64(reg.expiry_unix)) {
    return std::nullopt;
  }
  std::uint16_t cred_len = 0;
  ByteSpan cred;
  if (!r.take_u16(cred_len) || cred_len > kMaxCredBlob || !r.take(cred_len, cred) ||
      !r.rest().empty()) {
    return std::nullopt;
  }
  reg.credential.assign(cred.begin(), cred.end());
  return reg;
}

std::vector<Byte> make_user_deregister(
    const tier::crypto::Ed25519PublicKey& user_pub, ByteSpan credential,
    std::uint64_t issued_unix) {
  // Same body as a register (so the communicator runs the identical credential
  // check), only the type byte differs and the expiry field is unused (0).
  std::vector<Byte> out;
  out.push_back(kUserDeregisterType);
  put_bytes(out, ByteSpan(user_pub.data(), user_pub.size()));
  put_u64(out, issued_unix);
  put_u64(out, 0);
  put_u16(out, static_cast<std::uint16_t>(credential.size()));
  put_bytes(out, credential);
  return out;
}

std::optional<UserRegister> open_user_deregister(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kUserDeregisterType) return std::nullopt;

  UserRegister reg;
  ByteSpan pub;
  if (!r.take(reg.user_pub.size(), pub)) return std::nullopt;
  std::memcpy(reg.user_pub.data(), pub.data(), reg.user_pub.size());
  if (!r.take_u64(reg.issued_unix) || !r.take_u64(reg.expiry_unix)) {
    return std::nullopt;
  }
  std::uint16_t cred_len = 0;
  ByteSpan cred;
  if (!r.take_u16(cred_len) || cred_len > kMaxCredBlob || !r.take(cred_len, cred) ||
      !r.rest().empty()) {
    return std::nullopt;
  }
  reg.credential.assign(cred.begin(), cred.end());
  return reg;
}

std::vector<Byte> make_user_lookup(const tier::core::PeerId& user_id) {
  std::vector<Byte> out;
  out.push_back(kUserLookupType);
  put_bytes(out, ByteSpan(user_id.data(), user_id.size()));
  return out;
}

std::optional<tier::core::PeerId> open_user_lookup(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kUserLookupType) return std::nullopt;
  tier::core::PeerId user_id{};
  ByteSpan u;
  if (!r.take(user_id.size(), u) || !r.rest().empty()) return std::nullopt;
  std::memcpy(user_id.data(), u.data(), user_id.size());
  return user_id;
}

std::vector<Byte> make_user_result(const tier::core::PeerId& queried_user,
                                   const std::vector<tier::core::PeerId>& device_ids) {
  std::vector<Byte> out;
  out.push_back(kUserResultType);
  put_bytes(out, ByteSpan(queried_user.data(), queried_user.size()));
  const std::size_t count =
      device_ids.size() > kMaxDevicesPerUser ? kMaxDevicesPerUser : device_ids.size();
  put_u16(out, static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    put_bytes(out, ByteSpan(device_ids[i].data(), device_ids[i].size()));
  }
  return out;
}

std::optional<UserResult> open_user_result(const tier::core::PeerId& expected,
                                           ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kUserResultType) return std::nullopt;

  UserResult res;
  ByteSpan u;
  if (!r.take(res.user_id.size(), u)) return std::nullopt;
  std::memcpy(res.user_id.data(), u.data(), res.user_id.size());
  if (res.user_id != expected) return std::nullopt;

  std::uint16_t count = 0;
  if (!r.take_u16(count) || count > kMaxDevicesPerUser) return std::nullopt;
  for (std::uint16_t i = 0; i < count; ++i) {
    tier::core::PeerId d{};
    ByteSpan db;
    if (!r.take(d.size(), db)) return std::nullopt;
    std::memcpy(d.data(), db.data(), d.size());
    res.device_ids.push_back(d);
  }
  if (!r.rest().empty()) return std::nullopt;
  return res;
}

}  // namespace tier::msg
