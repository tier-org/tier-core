#include "tier/crypto/kx.hpp"

#include <cstddef>

#include <openssl/evp.h>

#include "openssl_backend.hpp"

namespace tier::crypto {
namespace {

X25519PublicKey public_from_pkey(EVP_PKEY* pkey) {
  X25519PublicKey pub{};
  std::size_t len = pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 ||
      len != pub.size()) {
    detail::throw_ossl("EVP_PKEY_get_raw_public_key(X25519)");
  }
  return pub;
}

}  // namespace

X25519KeyPair x25519_generate() {
  detail::EvpPkey pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519"));
  if (!pkey) {
    detail::throw_ossl("EVP_PKEY_Q_keygen(X25519)");
  }
  X25519KeyPair kp;
  std::size_t len = kp.secret.size();
  if (EVP_PKEY_get_raw_private_key(pkey.get(), kp.secret.data(), &len) != 1 ||
      len != kp.secret.size()) {
    detail::throw_ossl("EVP_PKEY_get_raw_private_key(X25519)");
  }
  kp.public_key = public_from_pkey(pkey.get());
  return kp;
}

X25519KeyPair x25519_from_secret(const X25519SecretKey& secret) {
  detail::EvpPkey pkey(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, secret.data(), secret.size()));
  if (!pkey) {
    detail::throw_ossl("EVP_PKEY_new_raw_private_key(X25519)");
  }
  X25519KeyPair kp;
  kp.secret = secret;
  kp.public_key = public_from_pkey(pkey.get());
  return kp;
}

std::optional<std::array<Byte, kX25519KeySize>> x25519_ecdh(
    const X25519SecretKey& secret, const X25519PublicKey& peer_public) {
  detail::EvpPkey priv(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, secret.data(), secret.size()));
  if (!priv) {
    detail::throw_ossl("EVP_PKEY_new_raw_private_key(X25519)");
  }
  detail::EvpPkey peer(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public.data(), peer_public.size()));
  if (!peer) {
    detail::throw_ossl("EVP_PKEY_new_raw_public_key(X25519)");
  }

  struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* c) const noexcept { EVP_PKEY_CTX_free(c); }
  };
  std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
      EVP_PKEY_CTX_new(priv.get(), nullptr));
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) {
    detail::throw_ossl("EVP_PKEY_derive setup(X25519)");
  }
  std::array<Byte, kX25519KeySize> shared{};
  std::size_t len = shared.size();
  // A failure here includes OpenSSL's rejection of an all-zero shared secret
  // (RFC 7748 small-subgroup check): report it as an open failure, not a throw.
  if (EVP_PKEY_derive(ctx.get(), shared.data(), &len) != 1 ||
      len != shared.size()) {
    return std::nullopt;
  }
  return shared;
}

}  // namespace tier::crypto
