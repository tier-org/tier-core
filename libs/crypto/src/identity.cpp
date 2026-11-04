#include "tier/crypto/identity.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "openssl_backend.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/kdf.hpp"

namespace tier::crypto {
namespace {

detail::EvpPkey pkey_from_seed(const Ed25519Seed& seed) {
  detail::EvpPkey pkey(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
  if (!pkey) {
    detail::throw_ossl("EVP_PKEY_new_raw_private_key");
  }
  return pkey;
}

Ed25519PublicKey public_from_pkey(EVP_PKEY* pkey) {
  Ed25519PublicKey pub{};
  std::size_t len = pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 ||
      len != pub.size()) {
    detail::throw_ossl("EVP_PKEY_get_raw_public_key");
  }
  return pub;
}

}  // namespace

NodeIdentity::NodeIdentity(Ed25519Signer signer) noexcept
    : signer_(std::move(signer)) {}

NodeIdentity NodeIdentity::generate() {
  detail::EvpPkey pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
  if (!pkey) {
    detail::throw_ossl("EVP_PKEY_Q_keygen");
  }
  Ed25519Seed seed{};
  std::size_t len = seed.size();
  if (EVP_PKEY_get_raw_private_key(pkey.get(), seed.data(), &len) != 1 ||
      len != seed.size()) {
    detail::throw_ossl("EVP_PKEY_get_raw_private_key");
  }
  return NodeIdentity(Ed25519Signer(seed, public_from_pkey(pkey.get())));
}

NodeIdentity NodeIdentity::from_seed(ByteSpan seed) {
  if (seed.size() != kEd25519SeedSize) {
    throw std::invalid_argument("Ed25519 seed must be 32 bytes");
  }
  Ed25519Seed seed_copy{};
  std::copy(seed.begin(), seed.end(), seed_copy.begin());
  detail::EvpPkey pkey = pkey_from_seed(seed_copy);
  return NodeIdentity(Ed25519Signer(seed_copy, public_from_pkey(pkey.get())));
}

std::vector<Byte> NodeIdentity::self_signed_certificate_der() const {
  detail::EvpPkey pkey = pkey_from_seed(seed());

  std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
  if (!cert) {
    detail::throw_ossl("X509_new");
  }
  X509_set_version(cert.get(), 2);  // X.509 v3
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3650L * 24 * 3600);
  if (X509_set_pubkey(cert.get(), pkey.get()) != 1) {
    detail::throw_ossl("X509_set_pubkey");
  }
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("tierd"), -1,
                             -1, 0);
  X509_set_issuer_name(cert.get(), name);  // self-signed: issuer == subject
  // Ed25519 (PureEdDSA) is signed with a NULL message digest.
  if (X509_sign(cert.get(), pkey.get(), nullptr) == 0) {
    detail::throw_ossl("X509_sign");
  }

  unsigned char* der = nullptr;
  const int len = i2d_X509(cert.get(), &der);
  if (len <= 0) {
    detail::throw_ossl("i2d_X509");
  }
  std::vector<Byte> out(der, der + len);
  OPENSSL_free(der);
  return out;
}

namespace {

// Domain-separation context strings for deriving the encryption keys from the
// identity seed. Changing a string rotates that derived key, so they are fixed.
constexpr char kX25519Info[] = "tier identity x25519 v1";
constexpr char kMlKemInfo[] = "tier identity ml-kem-768 v1";

ByteSpan as_span(const char* s) {
  return ByteSpan(reinterpret_cast<const Byte*>(s),
                  std::char_traits<char>::length(s));
}

}  // namespace

X25519KeyPair NodeIdentity::x25519_identity_key() const {
  const Ed25519Seed& s = seed();
  std::vector<Byte> material =
      hkdf_sha256(ByteSpan(s.data(), s.size()), ByteSpan(), as_span(kX25519Info),
                  kX25519KeySize);
  X25519SecretKey secret{};
  std::copy(material.begin(), material.end(), secret.begin());
  return x25519_from_secret(secret);
}

MlKem768KeyPair NodeIdentity::mlkem768_identity_key() const {
  const Ed25519Seed& s = seed();
  std::vector<Byte> material =
      hkdf_sha256(ByteSpan(s.data(), s.size()), ByteSpan(), as_span(kMlKemInfo),
                  kMlKem768SeedSize);
  MlKem768Seed kem_seed{};
  std::copy(material.begin(), material.end(), kem_seed.begin());
  return mlkem768_from_seed(kem_seed);
}

std::vector<Byte> NodeIdentity::private_key_pkcs8_der() const {
  detail::EvpPkey pkey = pkey_from_seed(seed());
  std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> p8(
      EVP_PKEY2PKCS8(pkey.get()), PKCS8_PRIV_KEY_INFO_free);
  if (!p8) {
    detail::throw_ossl("EVP_PKEY2PKCS8");
  }
  unsigned char* der = nullptr;
  const int len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &der);
  if (len <= 0) {
    detail::throw_ossl("i2d_PKCS8_PRIV_KEY_INFO");
  }
  std::vector<Byte> out(der, der + len);
  OPENSSL_free(der);
  return out;
}

}  // namespace tier::crypto
