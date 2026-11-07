#include "tier/crypto/kdf.hpp"

#include <stdexcept>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include "openssl_backend.hpp"

namespace tier::crypto {

std::vector<Byte> hkdf_sha256(ByteSpan ikm, ByteSpan salt, ByteSpan info,
                              std::size_t out_len) {
  // SHA-256 HKDF can expand at most 255 * HashLen bytes.
  if (out_len == 0 || out_len > 255U * kDigest256Size) {
    throw std::runtime_error("HKDF-SHA256: invalid output length");
  }

  struct KdfDeleter {
    void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); }
  };
  struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); }
  };
  std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF",
                                                         nullptr));
  if (!kdf) {
    detail::throw_ossl("EVP_KDF_fetch(HKDF)");
  }
  std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
  if (!ctx) {
    detail::throw_ossl("EVP_KDF_CTX_new");
  }

  // Build the parameter set. The digest and key are always present; salt and
  // info are added only when non-empty so an empty span never becomes a
  // null-pointer octet string.
  char digest[] = "SHA256";
  OSSL_PARAM params[5];
  int n = 0;
  params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest,
                                                 0);
  params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_KEY, const_cast<Byte*>(ikm.data()), ikm.size());
  if (!salt.empty()) {
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<Byte*>(salt.data()), salt.size());
  }
  if (!info.empty()) {
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, const_cast<Byte*>(info.data()), info.size());
  }
  params[n] = OSSL_PARAM_construct_end();

  std::vector<Byte> out(out_len);
  if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1) {
    detail::throw_ossl("EVP_KDF_derive(HKDF)");
  }
  return out;
}

std::vector<Byte> pbkdf2_sha256(ByteSpan password, ByteSpan salt,
                                std::uint32_t iterations, std::size_t out_len) {
  if (out_len == 0 || iterations == 0) {
    throw std::runtime_error("PBKDF2-SHA256: invalid output length or rounds");
  }

  struct KdfDeleter {
    void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); }
  };
  struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); }
  };
  std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "PBKDF2",
                                                         nullptr));
  if (!kdf) {
    detail::throw_ossl("EVP_KDF_fetch(PBKDF2)");
  }
  std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
  if (!ctx) {
    detail::throw_ossl("EVP_KDF_CTX_new");
  }

  char digest[] = "SHA256";
  auto iter = static_cast<unsigned int>(iterations);
  OSSL_PARAM params[5];
  int n = 0;
  params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest,
                                                 0);
  params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_PASSWORD, const_cast<Byte*>(password.data()),
      password.size());
  params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, const_cast<Byte*>(salt.data()), salt.size());
  params[n++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
  params[n] = OSSL_PARAM_construct_end();

  std::vector<Byte> out(out_len);
  if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1) {
    detail::throw_ossl("EVP_KDF_derive(PBKDF2)");
  }
  return out;
}

}  // namespace tier::crypto
