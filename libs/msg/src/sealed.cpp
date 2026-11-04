#include "tier/msg/sealed.hpp"

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>

#include "tier/core/control.hpp"
#include "tier/crypto/aead.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/kdf.hpp"

namespace tier::msg {
namespace {

using tier::crypto::Byte;

// Domain-separation tags. Each context has its own tag so a byte string signed
// or authenticated in one role can never be reused in another.
constexpr char kHeaderTag[] = "tier-msg-hdr-v1";
constexpr char kSigTag[] = "tier-msg-sig-v1";
constexpr char kEncKeysTag[] = "tier-enc-keys-v1";

constexpr std::uint8_t kSealedType =
    static_cast<std::uint8_t>(tier::core::ControlType::app_sealed);
constexpr std::uint8_t kEncKeysType =
    static_cast<std::uint8_t>(tier::core::ControlType::enc_keys);

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

void put_bytes(std::vector<Byte>& out, ByteSpan b) {
  out.insert(out.end(), b.begin(), b.end());
}

void put_network(std::vector<Byte>& out, std::string_view network) {
  put_u16(out, static_cast<std::uint16_t>(network.size()));
  out.insert(out.end(), network.begin(), network.end());
}

bool suite_has_x25519(Suite s) { return s == Suite::classical || s == Suite::hybrid; }
bool suite_has_mlkem(Suite s) { return s == Suite::pq || s == Suite::hybrid; }

// The authenticated header: bound into the AEAD aad and into the HKDF info, and
// signed by the sender. Identical construction on seal and open.
std::vector<Byte> build_header(std::string_view network, Suite suite,
                               const tier::core::PeerId& sender_id,
                               const tier::core::PeerId& recipient_id,
                               const tier::crypto::X25519PublicKey* epk,
                               const tier::crypto::MlKem768Ciphertext* kem_ct,
                               const tier::crypto::AeadNonce& nonce) {
  std::vector<Byte> h;
  put_tag(h, kHeaderTag);
  put_network(h, network);
  h.push_back(static_cast<Byte>(suite));
  put_bytes(h, ByteSpan(sender_id.data(), sender_id.size()));
  put_bytes(h, ByteSpan(recipient_id.data(), recipient_id.size()));
  h.push_back(epk != nullptr ? 1 : 0);
  if (epk != nullptr) put_bytes(h, ByteSpan(epk->data(), epk->size()));
  h.push_back(kem_ct != nullptr ? 1 : 0);
  if (kem_ct != nullptr) put_bytes(h, ByteSpan(kem_ct->data(), kem_ct->size()));
  put_bytes(h, ByteSpan(nonce.data(), nonce.size()));
  return h;
}

// What the sender signs: a tag, the header, and the length-prefixed ciphertext.
std::vector<Byte> build_sig_input(const std::vector<Byte>& header, ByteSpan ct) {
  std::vector<Byte> m;
  put_tag(m, kSigTag);
  put_bytes(m, ByteSpan(header.data(), header.size()));
  put_u32(m, static_cast<std::uint32_t>(ct.size()));
  put_bytes(m, ct);
  return m;
}

tier::core::PeerId id_of(const tier::crypto::Ed25519PublicKey& pub) {
  const tier::crypto::Digest256 d =
      tier::crypto::sha256(ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId id{};
  std::memcpy(id.data(), d.data(), id.size());
  return id;
}

// Derive the 32-byte AEAD key from the suite's shared secret(s), bound to the
// full header via HKDF info.
tier::crypto::AeadKey derive_key(ByteSpan ikm, const std::vector<Byte>& header) {
  const std::vector<Byte> material = tier::crypto::hkdf_sha256(
      ikm, ByteSpan(), ByteSpan(header.data(), header.size()),
      tier::crypto::kAeadKeySize);
  tier::crypto::AeadKey key{};
  std::memcpy(key.data(), material.data(), key.size());
  return key;
}

// A minimal bounds-checked reader over untrusted input.
class Reader {
 public:
  explicit Reader(ByteSpan in) : in_(in) {}
  bool take(std::size_t n, ByteSpan& out) {
    if (n > in_.size() - pos_ || pos_ > in_.size()) return false;
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
  [[nodiscard]] bool done() const { return pos_ == in_.size(); }

 private:
  ByteSpan in_;
  std::size_t pos_ = 0;
};

bool verify_sig(const tier::crypto::Ed25519PublicKey& pub, ByteSpan message,
                ByteSpan signature) {
  tier::crypto::Ed25519Verifier v(pub);
  return v.verify(message, signature);
}

}  // namespace

bool is_known_suite(std::uint8_t v) noexcept {
  return v == static_cast<std::uint8_t>(Suite::classical) ||
         v == static_cast<std::uint8_t>(Suite::hybrid) ||
         v == static_cast<std::uint8_t>(Suite::pq);
}

std::vector<Byte> make_enc_keys_announce(const tier::crypto::NodeIdentity& self,
                                         std::string_view network) {
  const auto x = self.x25519_identity_key();
  const auto k = self.mlkem768_identity_key();

  std::vector<Byte> signed_input;
  put_tag(signed_input, kEncKeysTag);
  put_network(signed_input, network);
  put_bytes(signed_input, ByteSpan(x.public_key.data(), x.public_key.size()));
  put_bytes(signed_input, ByteSpan(k.public_key.data(), k.public_key.size()));
  const std::vector<Byte> sig = self.signer().sign(
      ByteSpan(signed_input.data(), signed_input.size()));

  std::vector<Byte> out;
  out.push_back(kEncKeysType);
  put_bytes(out, ByteSpan(x.public_key.data(), x.public_key.size()));
  put_bytes(out, ByteSpan(k.public_key.data(), k.public_key.size()));
  out.push_back(static_cast<Byte>(sig.size()));
  put_bytes(out, ByteSpan(sig.data(), sig.size()));
  return out;
}

std::optional<PeerEncKeys> open_enc_keys_announce(
    std::string_view network, const tier::crypto::Ed25519PublicKey& sender_identity,
    ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kEncKeysType) return std::nullopt;

  PeerEncKeys keys;
  ByteSpan x;
  ByteSpan k;
  if (!r.take(keys.x25519.size(), x) || !r.take(keys.mlkem.size(), k)) {
    return std::nullopt;
  }
  std::memcpy(keys.x25519.data(), x.data(), keys.x25519.size());
  std::memcpy(keys.mlkem.data(), k.data(), keys.mlkem.size());

  std::uint8_t sig_len = 0;
  ByteSpan sig;
  if (!r.take_u8(sig_len) || !r.take(sig_len, sig) || !r.done()) {
    return std::nullopt;
  }

  std::vector<Byte> signed_input;
  put_tag(signed_input, kEncKeysTag);
  put_network(signed_input, network);
  put_bytes(signed_input, x);
  put_bytes(signed_input, k);
  if (!verify_sig(sender_identity, ByteSpan(signed_input.data(), signed_input.size()),
                  sig)) {
    return std::nullopt;
  }
  return keys;
}

std::vector<Byte> seal(const tier::crypto::NodeIdentity& sender,
                       std::string_view network, Suite suite,
                       const Recipient& recipient, ByteSpan plaintext) {
  if (plaintext.size() > kMaxSealedPlaintext) {
    throw std::length_error("tier::msg::seal: plaintext exceeds frame budget");
  }

  const tier::core::PeerId sender_id = id_of(sender.public_key());

  // Build the ephemeral key material per suite.
  std::optional<tier::crypto::X25519PublicKey> epk;
  std::optional<tier::crypto::MlKem768Ciphertext> kem_ct;
  std::vector<Byte> ikm;
  if (suite_has_x25519(suite)) {
    const auto eph = tier::crypto::x25519_generate();
    const auto shared = tier::crypto::x25519_ecdh(eph.secret, recipient.keys.x25519);
    if (!shared) {
      throw std::runtime_error("tier::msg::seal: X25519 ECDH failed");
    }
    epk = eph.public_key;
    ikm.insert(ikm.end(), shared->begin(), shared->end());
  }
  if (suite_has_mlkem(suite)) {
    const auto enc = tier::crypto::mlkem768_encapsulate(recipient.keys.mlkem);
    kem_ct = enc.ciphertext;
    ikm.insert(ikm.end(), enc.shared_secret.begin(), enc.shared_secret.end());
  }

  // Random per-message nonce. The AEAD key is already unique per message (fresh
  // ephemeral/KEM secret), so a random nonce carries no reuse risk.
  tier::crypto::AeadNonce nonce{};
  {
    const auto rnd = tier::crypto::hkdf_sha256(
        ByteSpan(ikm.data(), ikm.size()), ByteSpan(),
        ByteSpan(reinterpret_cast<const Byte*>("nonce"), 5), nonce.size());
    std::memcpy(nonce.data(), rnd.data(), nonce.size());
  }

  const std::vector<Byte> header = build_header(
      network, suite, sender_id, recipient.id,
      epk ? &*epk : nullptr, kem_ct ? &*kem_ct : nullptr, nonce);
  const tier::crypto::AeadKey key = derive_key(ByteSpan(ikm.data(), ikm.size()), header);
  const std::vector<Byte> ct = tier::crypto::aead_seal(
      key, nonce, ByteSpan(header.data(), header.size()), plaintext);

  const std::vector<Byte> sig_input = build_sig_input(header, ByteSpan(ct.data(), ct.size()));
  const std::vector<Byte> sig = sender.signer().sign(
      ByteSpan(sig_input.data(), sig_input.size()));

  std::vector<Byte> out;
  out.push_back(kSealedType);
  out.push_back(static_cast<Byte>(suite));
  put_bytes(out, ByteSpan(sender_id.data(), sender_id.size()));
  put_bytes(out, ByteSpan(recipient.id.data(), recipient.id.size()));
  out.push_back(epk ? 1 : 0);
  if (epk) put_bytes(out, ByteSpan(epk->data(), epk->size()));
  out.push_back(kem_ct ? 1 : 0);
  if (kem_ct) put_bytes(out, ByteSpan(kem_ct->data(), kem_ct->size()));
  put_bytes(out, ByteSpan(nonce.data(), nonce.size()));
  put_u32(out, static_cast<std::uint32_t>(ct.size()));
  put_bytes(out, ByteSpan(ct.data(), ct.size()));
  out.push_back(static_cast<Byte>(sig.size()));
  put_bytes(out, ByteSpan(sig.data(), sig.size()));
  return out;
}

std::optional<Opened> open(const tier::crypto::NodeIdentity& recipient,
                           std::string_view network,
                           const tier::crypto::Ed25519PublicKey& sender_identity,
                           ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  std::uint8_t suite_byte = 0;
  if (!r.take_u8(type) || type != kSealedType) return std::nullopt;
  if (!r.take_u8(suite_byte) || !is_known_suite(suite_byte)) return std::nullopt;
  const Suite suite = static_cast<Suite>(suite_byte);

  tier::core::PeerId sender_id{};
  tier::core::PeerId recipient_id{};
  ByteSpan sid;
  ByteSpan rid;
  if (!r.take(sender_id.size(), sid) || !r.take(recipient_id.size(), rid)) {
    return std::nullopt;
  }
  std::memcpy(sender_id.data(), sid.data(), sender_id.size());
  std::memcpy(recipient_id.data(), rid.data(), recipient_id.size());

  std::uint8_t epk_flag = 0;
  tier::crypto::X25519PublicKey epk{};
  bool have_epk = false;
  if (!r.take_u8(epk_flag)) return std::nullopt;
  if (epk_flag == 1) {
    ByteSpan s;
    if (!r.take(epk.size(), s)) return std::nullopt;
    std::memcpy(epk.data(), s.data(), epk.size());
    have_epk = true;
  } else if (epk_flag != 0) {
    return std::nullopt;
  }

  std::uint8_t kem_flag = 0;
  tier::crypto::MlKem768Ciphertext kem_ct{};
  bool have_kem = false;
  if (!r.take_u8(kem_flag)) return std::nullopt;
  if (kem_flag == 1) {
    ByteSpan s;
    if (!r.take(kem_ct.size(), s)) return std::nullopt;
    std::memcpy(kem_ct.data(), s.data(), kem_ct.size());
    have_kem = true;
  } else if (kem_flag != 0) {
    return std::nullopt;
  }

  // The present fields must match what the suite requires.
  if (have_epk != suite_has_x25519(suite) || have_kem != suite_has_mlkem(suite)) {
    return std::nullopt;
  }

  tier::crypto::AeadNonce nonce{};
  ByteSpan ns;
  if (!r.take(nonce.size(), ns)) return std::nullopt;
  std::memcpy(nonce.data(), ns.data(), nonce.size());

  std::uint32_t ct_len = 0;
  ByteSpan ct;
  if (!r.take_u32(ct_len) || !r.take(ct_len, ct)) return std::nullopt;

  std::uint8_t sig_len = 0;
  ByteSpan sig;
  if (!r.take_u8(sig_len) || !r.take(sig_len, sig) || !r.done()) {
    return std::nullopt;
  }

  // Authenticate the sender: the claimed id must hash to the connection's
  // identity key, and the signature must verify under it.
  if (id_of(sender_identity) != sender_id) return std::nullopt;

  const std::vector<Byte> header = build_header(
      network, suite, sender_id, recipient_id, have_epk ? &epk : nullptr,
      have_kem ? &kem_ct : nullptr, nonce);
  const std::vector<Byte> sig_input = build_sig_input(header, ct);
  if (!verify_sig(sender_identity, ByteSpan(sig_input.data(), sig_input.size()), sig)) {
    return std::nullopt;
  }

  // Must be addressed to us.
  if (recipient_id != id_of(recipient.public_key())) return std::nullopt;

  // Recompute the shared secret(s) with our identity keys.
  std::vector<Byte> ikm;
  if (suite_has_x25519(suite)) {
    const auto x = recipient.x25519_identity_key();
    const auto shared = tier::crypto::x25519_ecdh(x.secret, epk);
    if (!shared) return std::nullopt;
    ikm.insert(ikm.end(), shared->begin(), shared->end());
  }
  if (suite_has_mlkem(suite)) {
    const auto k = recipient.mlkem768_identity_key();
    const auto ss = tier::crypto::mlkem768_decapsulate(k.seed, kem_ct);
    if (!ss) return std::nullopt;
    ikm.insert(ikm.end(), ss->begin(), ss->end());
  }

  const tier::crypto::AeadKey key = derive_key(ByteSpan(ikm.data(), ikm.size()), header);
  auto pt = tier::crypto::aead_open(key, nonce, ByteSpan(header.data(), header.size()), ct);
  if (!pt) return std::nullopt;

  Opened out;
  out.sender_id = sender_id;
  out.suite = suite;
  out.plaintext = std::move(*pt);
  return out;
}

}  // namespace tier::msg
