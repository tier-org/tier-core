#include "tier/crypto/identity.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <utility>
#include <vector>

// wolf_backend.hpp includes <wolfssl/options.h> first; that must precede every
// other wolfSSL header, so asn_public.h is included only after it.
#include "wolf_backend.hpp"

#include <wolfssl/wolfcrypt/asn_public.h>

#include "tier/crypto/ed25519.hpp"

namespace tier::crypto {
namespace {

// Generous upper bound for a DER-encoded Ed25519 self-signed certificate
// (key + signature are 32/64 bytes; the rest is a small fixed structure).
constexpr std::size_t kMaxCertificateDer = 2048;

}  // namespace

NodeIdentity::NodeIdentity(Ed25519Signer signer) noexcept
    : signer_(std::move(signer)) {}

NodeIdentity NodeIdentity::generate() {
  detail::Rng rng;
  detail::Ed25519Key key;

  const int make_rc = wc_ed25519_make_key(rng.get(), ED25519_KEY_SIZE, key.get());
  if (make_rc != 0) {
    detail::throw_wolf("wc_ed25519_make_key", make_rc);
  }

  Ed25519Seed seed{};
  auto seed_len = static_cast<word32>(seed.size());
  const int seed_rc = wc_ed25519_export_private_only(key.get(), seed.data(), &seed_len);
  if (seed_rc != 0) {
    detail::throw_wolf("wc_ed25519_export_private_only", seed_rc);
  }

  Ed25519PublicKey pub{};
  auto pub_len = static_cast<word32>(pub.size());
  const int pub_rc = wc_ed25519_export_public(key.get(), pub.data(), &pub_len);
  if (pub_rc != 0) {
    detail::throw_wolf("wc_ed25519_export_public", pub_rc);
  }

  return NodeIdentity(Ed25519Signer(seed, pub));
}

NodeIdentity NodeIdentity::from_seed(ByteSpan seed) {
  if (seed.size() != kEd25519SeedSize) {
    throw std::invalid_argument("Ed25519 seed must be 32 bytes");
  }

  detail::Ed25519Key key;
  const int import_rc = wc_ed25519_import_private_only(
      seed.data(), static_cast<word32>(seed.size()), key.get());
  if (import_rc != 0) {
    detail::throw_wolf("wc_ed25519_import_private_only", import_rc);
  }

  Ed25519PublicKey pub{};
  const int make_pub_rc =
      wc_ed25519_make_public(key.get(), pub.data(), static_cast<word32>(pub.size()));
  if (make_pub_rc != 0) {
    detail::throw_wolf("wc_ed25519_make_public", make_pub_rc);
  }

  Ed25519Seed seed_copy{};
  std::copy(seed.begin(), seed.end(), seed_copy.begin());
  return NodeIdentity(Ed25519Signer(seed_copy, pub));
}

std::vector<Byte> NodeIdentity::self_signed_certificate_der() const {
  detail::Rng rng;
  detail::Ed25519Key key;

  const int import_rc = wc_ed25519_import_private_key(
      seed().data(), static_cast<word32>(seed().size()),
      public_key().data(), static_cast<word32>(public_key().size()), key.get());
  if (import_rc != 0) {
    detail::throw_wolf("wc_ed25519_import_private_key", import_rc);
  }

  Cert cert;
  const int init_rc = wc_InitCert(&cert);
  if (init_rc != 0) {
    detail::throw_wolf("wc_InitCert", init_rc);
  }
  cert.sigType = CTC_ED25519;
  cert.daysValid = 3650;
  cert.isCA = 0;
  std::snprintf(cert.subject.commonName, CTC_NAME_SIZE, "%s", "tierd");

  std::vector<Byte> der(kMaxCertificateDer);
  const int body_sz = wc_MakeCert_ex(&cert, der.data(),
                                     static_cast<word32>(der.size()),
                                     ED25519_TYPE, key.get(), rng.get());
  if (body_sz < 0) {
    detail::throw_wolf("wc_MakeCert_ex", body_sz);
  }

  const int total_sz = wc_SignCert_ex(cert.bodySz, cert.sigType, der.data(),
                                      static_cast<word32>(der.size()),
                                      ED25519_TYPE, key.get(), rng.get());
  if (total_sz < 0) {
    detail::throw_wolf("wc_SignCert_ex", total_sz);
  }

  der.resize(static_cast<std::size_t>(total_sz));
  return der;
}

std::vector<Byte> NodeIdentity::private_key_pkcs8_der() const {
  detail::Ed25519Key key;
  const int import_rc = wc_ed25519_import_private_key(
      seed().data(), static_cast<word32>(seed().size()),
      public_key().data(), static_cast<word32>(public_key().size()), key.get());
  if (import_rc != 0) {
    detail::throw_wolf("wc_ed25519_import_private_key", import_rc);
  }

  // An Ed25519 PKCS#8 private key is well under 128 bytes.
  std::vector<Byte> der(128);
  const int len =
      wc_Ed25519PrivateKeyToDer(key.get(), der.data(), static_cast<word32>(der.size()));
  if (len < 0) {
    detail::throw_wolf("wc_Ed25519PrivateKeyToDer", len);
  }
  der.resize(static_cast<std::size_t>(len));
  return der;
}

}  // namespace tier::crypto
