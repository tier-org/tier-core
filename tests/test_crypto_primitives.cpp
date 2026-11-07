// Known-answer and property tests for the message-layer crypto primitives:
// HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 (RFC 8439), X25519 (RFC 7748) and
// ML-KEM-768 (FIPS 203, round-trip / determinism / cross-key).
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "tier/crypto/aead.hpp"
#include "tier/crypto/kdf.hpp"
#include "tier/crypto/kem.hpp"
#include "tier/crypto/kx.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::crypto::Byte;

std::vector<Byte> unhex(const std::string& h) {
  std::vector<Byte> out;
  out.reserve(h.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
  };
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    out.push_back(static_cast<Byte>((nib(h[i]) << 4) | nib(h[i + 1])));
  }
  return out;
}

template <std::size_t N>
std::array<Byte, N> to_array(const std::vector<Byte>& v) {
  std::array<Byte, N> a{};
  for (std::size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
  return a;
}

tier::crypto::ByteSpan span(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

void test_hkdf() {
  // RFC 5869, Test Case 1 (SHA-256).
  const auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const auto salt = unhex("000102030405060708090a0b0c");
  const auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
  const auto okm = tier::crypto::hkdf_sha256(span(ikm), span(salt), span(info), 42);
  const auto want = unhex(
      "3cb25f25faacd57a90434f64d0362f2a"
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865");
  check(okm == want, "HKDF-SHA256 RFC 5869 TC1 OKM");

  // Empty salt and info are accepted and produce stable, non-empty output.
  const auto okm2 = tier::crypto::hkdf_sha256(span(ikm), tier::crypto::ByteSpan(),
                                              tier::crypto::ByteSpan(), 32);
  const auto okm3 = tier::crypto::hkdf_sha256(span(ikm), tier::crypto::ByteSpan(),
                                              tier::crypto::ByteSpan(), 32);
  check(okm2.size() == 32 && okm2 == okm3, "HKDF empty salt/info deterministic");

  // A different info gives different key material (domain separation works).
  const auto a = unhex("66");
  const auto b = unhex("67");
  check(tier::crypto::hkdf_sha256(span(ikm), tier::crypto::ByteSpan(), span(a), 32) !=
            tier::crypto::hkdf_sha256(span(ikm), tier::crypto::ByteSpan(), span(b), 32),
        "HKDF different info -> different output");
}

void test_pbkdf2() {
  // Well-known PBKDF2-HMAC-SHA256 vectors (P="password", S="salt").
  const auto pw = unhex("70617373776f7264");  // "password"
  const auto salt = unhex("73616c74");        // "salt"
  const auto c1 = tier::crypto::pbkdf2_sha256(span(pw), span(salt), 1, 32);
  check(c1 == unhex("120fb6cffcf8b32c43e7225256c4f837"
                    "a86548c92ccc35480805987cb70be17b"),
        "PBKDF2-SHA256 c=1 known answer");
  const auto c2 = tier::crypto::pbkdf2_sha256(span(pw), span(salt), 2, 32);
  check(c2 == unhex("ae4d0c95af6b46d32d0adff928f06dd0"
                    "2a303f8ef3c251dfd6e2d85a95474c43"),
        "PBKDF2-SHA256 c=2 known answer");

  // Different iteration counts and passwords diverge; same inputs are stable.
  check(c1 != c2, "PBKDF2 iteration count changes output");
  const auto bad = unhex("70617373776f7265");  // "passwore"
  check(tier::crypto::pbkdf2_sha256(span(bad), span(salt), 1, 32) != c1,
        "PBKDF2 different password -> different output");
  check(tier::crypto::pbkdf2_sha256(span(pw), span(salt), 1, 32) == c1,
        "PBKDF2 deterministic");
}

void test_aead() {
  // RFC 8439, Section 2.8.2.
  const auto key = to_array<tier::crypto::kAeadKeySize>(unhex(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
  const auto nonce =
      to_array<tier::crypto::kAeadNonceSize>(unhex("070000004041424344454647"));
  const auto aad = unhex("50515253c0c1c2c3c4c5c6c7");
  const std::string pt_str =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";
  const std::vector<Byte> pt(pt_str.begin(), pt_str.end());
  const auto want_ct = unhex(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116"
      "1ae10b594f09e26a7e902ecbd0600691");  // tag appended

  const auto sealed = tier::crypto::aead_seal(key, nonce, span(aad), span(pt));
  check(sealed == want_ct, "ChaCha20-Poly1305 RFC 8439 ciphertext+tag");

  const auto opened = tier::crypto::aead_open(key, nonce, span(aad), span(sealed));
  check(opened.has_value() && *opened == pt, "AEAD open round-trip");

  // Tamper: flip one ciphertext byte -> auth fails.
  auto bad = sealed;
  bad[0] ^= 0x01;
  check(!tier::crypto::aead_open(key, nonce, span(aad), span(bad)).has_value(),
        "AEAD open rejects flipped ciphertext");
  // Tamper: flip one tag byte -> auth fails.
  bad = sealed;
  bad[bad.size() - 1] ^= 0x01;
  check(!tier::crypto::aead_open(key, nonce, span(aad), span(bad)).has_value(),
        "AEAD open rejects flipped tag");
  // Wrong AAD -> auth fails.
  auto bad_aad = aad;
  bad_aad[0] ^= 0x01;
  check(!tier::crypto::aead_open(key, nonce, span(bad_aad), span(sealed)).has_value(),
        "AEAD open rejects wrong aad");
  // Truncated below tag size -> nullopt, no crash.
  const std::vector<Byte> tiny(8, 0);
  check(!tier::crypto::aead_open(key, nonce, span(aad), span(tiny)).has_value(),
        "AEAD open rejects too-short input");

  // Empty plaintext still authenticates (tag only).
  const auto empty_sealed =
      tier::crypto::aead_seal(key, nonce, span(aad), tier::crypto::ByteSpan());
  check(empty_sealed.size() == tier::crypto::kAeadTagSize, "AEAD empty pt -> tag only");
  const auto empty_open =
      tier::crypto::aead_open(key, nonce, span(aad), span(empty_sealed));
  check(empty_open.has_value() && empty_open->empty(), "AEAD empty pt round-trip");
}

void test_x25519() {
  // RFC 7748, Section 6.1.
  const auto a_priv =
      to_array<tier::crypto::kX25519KeySize>(unhex(
          "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
  const auto a_pub_want = unhex(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const auto b_priv =
      to_array<tier::crypto::kX25519KeySize>(unhex(
          "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
  const auto b_pub_want = unhex(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  const auto shared_want = unhex(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

  const auto a = tier::crypto::x25519_from_secret(a_priv);
  const auto b = tier::crypto::x25519_from_secret(b_priv);
  check(std::vector<Byte>(a.public_key.begin(), a.public_key.end()) == a_pub_want,
        "X25519 derive Alice public");
  check(std::vector<Byte>(b.public_key.begin(), b.public_key.end()) == b_pub_want,
        "X25519 derive Bob public");

  const auto ab = tier::crypto::x25519_ecdh(a_priv, b.public_key);
  const auto ba = tier::crypto::x25519_ecdh(b_priv, a.public_key);
  check(ab.has_value() &&
            std::vector<Byte>(ab->begin(), ab->end()) == shared_want,
        "X25519 ECDH shared matches RFC 7748");
  check(ba.has_value() && *ab == *ba, "X25519 ECDH symmetric");

  // An all-zero (low-order) peer key is rejected, not a crash.
  tier::crypto::X25519PublicKey zero{};
  check(!tier::crypto::x25519_ecdh(a_priv, zero).has_value(),
        "X25519 ECDH rejects low-order peer key");

  // A fresh ephemeral pair is well-formed and agrees with a static peer.
  const auto eph = tier::crypto::x25519_generate();
  const auto s1 = tier::crypto::x25519_ecdh(eph.secret, a.public_key);
  const auto s2 = tier::crypto::x25519_ecdh(a_priv, eph.public_key);
  check(s1 && s2 && *s1 == *s2, "X25519 ephemeral/static agree");
}

void test_mlkem() {
  tier::crypto::MlKem768Seed seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<Byte>(i * 3 + 1);

  const auto kp1 = tier::crypto::mlkem768_from_seed(seed);
  const auto kp2 = tier::crypto::mlkem768_from_seed(seed);
  check(kp1.public_key == kp2.public_key, "ML-KEM-768 keygen deterministic in seed");
  check(kp1.public_key.size() == tier::crypto::kMlKem768PublicKeySize,
        "ML-KEM-768 public key size");

  const auto enc = tier::crypto::mlkem768_encapsulate(kp1.public_key);
  check(enc.ciphertext.size() == tier::crypto::kMlKem768CiphertextSize,
        "ML-KEM-768 ciphertext size");
  const auto ss = tier::crypto::mlkem768_decapsulate(seed, enc.ciphertext);
  check(ss.has_value() && *ss == enc.shared_secret,
        "ML-KEM-768 encaps/decaps round-trip");

  // Two encapsulations to the same key differ (randomized) but each decaps back.
  const auto enc2 = tier::crypto::mlkem768_encapsulate(kp1.public_key);
  check(enc2.ciphertext != enc.ciphertext, "ML-KEM-768 encaps is randomized");
  const auto ss2 = tier::crypto::mlkem768_decapsulate(seed, enc2.ciphertext);
  check(ss2.has_value() && *ss2 == enc2.shared_secret, "ML-KEM-768 second round-trip");

  // Decapsulating someone else's ciphertext with the wrong key gives a
  // different secret (implicit rejection), never the sender's secret.
  tier::crypto::MlKem768Seed other_seed = seed;
  other_seed[0] ^= 0xFF;
  const auto wrong = tier::crypto::mlkem768_decapsulate(other_seed, enc.ciphertext);
  check(wrong.has_value() && *wrong != enc.shared_secret,
        "ML-KEM-768 wrong key -> different secret");
}

}  // namespace

int main() {
  test_hkdf();
  test_pbkdf2();
  test_aead();
  test_x25519();
  test_mlkem();
  if (g_failures == 0) {
    std::puts("crypto primitives: all checks passed");
  }
  return g_failures == 0 ? 0 : 1;
}
