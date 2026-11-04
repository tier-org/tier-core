#include "tier/crypto/kem.hpp"

#include <cstddef>
#include <memory>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "openssl_backend.hpp"

namespace tier::crypto {
namespace {

constexpr const char* kAlg = "ML-KEM-768";

struct PkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* c) const noexcept { EVP_PKEY_CTX_free(c); }
};
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;

// Build a full keypair EVP_PKEY from the 64-byte seed (deterministic keygen).
detail::EvpPkey keypair_from_seed(const MlKem768Seed& seed) {
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, kAlg, nullptr));
  if (!ctx) {
    detail::throw_ossl("EVP_PKEY_CTX_new_from_name(ML-KEM-768)");
  }
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_ML_KEM_SEED,
      const_cast<Byte*>(seed.data()), seed.size());
  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params) <= 0) {
    detail::throw_ossl("EVP_PKEY_fromdata(ML-KEM-768 seed)");
  }
  return detail::EvpPkey(raw);
}

// Build a public-only EVP_PKEY from the 1184-byte encapsulation key.
detail::EvpPkey public_from_bytes(const MlKem768PublicKey& pub) {
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, kAlg, nullptr));
  if (!ctx) {
    detail::throw_ossl("EVP_PKEY_CTX_new_from_name(ML-KEM-768)");
  }
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PUB_KEY, const_cast<Byte*>(pub.data()), pub.size());
  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    detail::throw_ossl("EVP_PKEY_fromdata(ML-KEM-768 pub)");
  }
  return detail::EvpPkey(raw);
}

}  // namespace

MlKem768KeyPair mlkem768_from_seed(const MlKem768Seed& seed) {
  detail::EvpPkey pkey = keypair_from_seed(seed);
  MlKem768KeyPair kp;
  kp.seed = seed;
  std::size_t len = kp.public_key.size();
  if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      kp.public_key.data(),
                                      kp.public_key.size(), &len) != 1 ||
      len != kp.public_key.size()) {
    detail::throw_ossl("EVP_PKEY_get_octet_string_param(ML-KEM-768 pub)");
  }
  return kp;
}

MlKem768Encapsulation mlkem768_encapsulate(const MlKem768PublicKey& public_key) {
  detail::EvpPkey pkey = public_from_bytes(public_key);
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
  if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    detail::throw_ossl("EVP_PKEY_encapsulate_init(ML-KEM-768)");
  }
  MlKem768Encapsulation out;
  std::size_t ct_len = out.ciphertext.size();
  std::size_t ss_len = out.shared_secret.size();
  if (EVP_PKEY_encapsulate(ctx.get(), out.ciphertext.data(), &ct_len,
                           out.shared_secret.data(), &ss_len) <= 0 ||
      ct_len != out.ciphertext.size() || ss_len != out.shared_secret.size()) {
    detail::throw_ossl("EVP_PKEY_encapsulate(ML-KEM-768)");
  }
  return out;
}

std::optional<MlKem768SharedSecret> mlkem768_decapsulate(
    const MlKem768Seed& seed, const MlKem768Ciphertext& ciphertext) {
  detail::EvpPkey pkey = keypair_from_seed(seed);
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
  if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    detail::throw_ossl("EVP_PKEY_decapsulate_init(ML-KEM-768)");
  }
  MlKem768SharedSecret ss{};
  std::size_t ss_len = ss.size();
  if (EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ss_len, ciphertext.data(),
                           ciphertext.size()) <= 0 ||
      ss_len != ss.size()) {
    return std::nullopt;
  }
  return ss;
}

}  // namespace tier::crypto
