#include "tier/crypto/aead.hpp"

#include <memory>
#include <stdexcept>

#include <openssl/evp.h>

#include "openssl_backend.hpp"

namespace tier::crypto {
namespace {

struct CipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* c) const noexcept { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

}  // namespace

std::vector<Byte> aead_seal(const AeadKey& key, const AeadNonce& nonce,
                            ByteSpan aad, ByteSpan plaintext) {
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    detail::throw_ossl("EVP_CIPHER_CTX_new");
  }
  if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(),
                         nonce.data()) != 1) {
    detail::throw_ossl("EVP_EncryptInit_ex(chacha20-poly1305)");
  }

  int len = 0;
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                        static_cast<int>(aad.size())) != 1) {
    detail::throw_ossl("EVP_EncryptUpdate(aad)");
  }

  std::vector<Byte> out(plaintext.size() + kAeadTagSize);
  int out_len = 0;
  if (!plaintext.empty() &&
      EVP_EncryptUpdate(ctx.get(), out.data(), &out_len, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    detail::throw_ossl("EVP_EncryptUpdate(plaintext)");
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + out_len, &final_len) != 1) {
    detail::throw_ossl("EVP_EncryptFinal_ex");
  }
  out_len += final_len;  // ChaCha20-Poly1305 is a stream cipher: final is 0.

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kAeadTagSize,
                          out.data() + out_len) != 1) {
    detail::throw_ossl("EVP_CTRL_AEAD_GET_TAG");
  }
  out.resize(static_cast<std::size_t>(out_len) + kAeadTagSize);
  return out;
}

std::optional<std::vector<Byte>> aead_open(const AeadKey& key,
                                           const AeadNonce& nonce, ByteSpan aad,
                                           ByteSpan ciphertext) {
  if (ciphertext.size() < kAeadTagSize) {
    return std::nullopt;
  }
  const std::size_t ct_len = ciphertext.size() - kAeadTagSize;
  const Byte* tag = ciphertext.data() + ct_len;

  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    detail::throw_ossl("EVP_CIPHER_CTX_new");
  }
  if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(),
                         nonce.data()) != 1) {
    detail::throw_ossl("EVP_DecryptInit_ex(chacha20-poly1305)");
  }

  int len = 0;
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                        static_cast<int>(aad.size())) != 1) {
    detail::throw_ossl("EVP_DecryptUpdate(aad)");
  }

  std::vector<Byte> out(ct_len);
  int out_len = 0;
  if (ct_len != 0 &&
      EVP_DecryptUpdate(ctx.get(), out.data(), &out_len, ciphertext.data(),
                        static_cast<int>(ct_len)) != 1) {
    detail::throw_ossl("EVP_DecryptUpdate(ciphertext)");
  }

  // Set the expected tag, then finalize: a non-positive return is an
  // authentication failure, not a backend error.
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kAeadTagSize,
                          const_cast<Byte*>(tag)) != 1) {
    detail::throw_ossl("EVP_CTRL_AEAD_SET_TAG");
  }
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + out_len, &final_len) <= 0) {
    return std::nullopt;  // tag mismatch: wrong key/nonce/aad or tampering
  }
  out.resize(static_cast<std::size_t>(out_len) +
             static_cast<std::size_t>(final_len));
  return out;
}

}  // namespace tier::crypto
