#include "tier/crypto/ed25519.hpp"

#include <cstddef>
#include <vector>

#include <openssl/evp.h>

#include "openssl_backend.hpp"

namespace tier::crypto {

Ed25519Verifier::Ed25519Verifier(const Ed25519PublicKey& public_key) noexcept
    : public_key_(public_key) {}

bool Ed25519Verifier::verify(ByteSpan message, ByteSpan signature) const {
  if (signature.size() != kEd25519SignatureSize) {
    return false;
  }
  detail::EvpPkey pkey(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, public_key_.data(), public_key_.size()));
  if (!pkey) {
    return false;
  }
  detail::EvpMdCtx ctx(EVP_MD_CTX_new());
  if (!ctx ||
      EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
    return false;
  }
  // Ed25519 is a one-shot (PureEdDSA) scheme: no streaming, md is NULL.
  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                          message.data(), message.size()) == 1;
}

Ed25519Signer::Ed25519Signer(const Ed25519Seed& seed,
                             const Ed25519PublicKey& public_key) noexcept
    : seed_(seed), public_key_(public_key) {}

std::vector<Byte> Ed25519Signer::sign(ByteSpan message) const {
  detail::EvpPkey pkey(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, seed_.data(), seed_.size()));
  if (!pkey) {
    detail::throw_ossl("EVP_PKEY_new_raw_private_key");
  }
  detail::EvpMdCtx ctx(EVP_MD_CTX_new());
  if (!ctx) {
    detail::throw_ossl("EVP_MD_CTX_new");
  }
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
    detail::throw_ossl("EVP_DigestSignInit");
  }
  std::size_t sig_len = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, message.data(),
                     message.size()) != 1) {
    detail::throw_ossl("EVP_DigestSign (size)");
  }
  std::vector<Byte> signature(sig_len);
  if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, message.data(),
                     message.size()) != 1) {
    detail::throw_ossl("EVP_DigestSign");
  }
  signature.resize(sig_len);
  return signature;
}

std::vector<Byte> Ed25519Signer::public_key() const {
  return std::vector<Byte>(public_key_.begin(), public_key_.end());
}

}  // namespace tier::crypto
