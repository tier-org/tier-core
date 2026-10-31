#pragma once

// Internal (non-installed) helpers over the OpenSSL EVP API: RAII wrappers and a
// uniform error path. Only translation units inside tier_crypto include this;
// OpenSSL types never cross into public headers.

#include <memory>
#include <stdexcept>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>

namespace tier::crypto::detail {

[[noreturn]] inline void throw_ossl(const char* what) {
  const unsigned long code = ERR_get_error();
  char buf[256] = {0};
  if (code != 0) {
    ERR_error_string_n(code, buf, sizeof(buf));
  }
  throw std::runtime_error(std::string(what) + " failed: " +
                           (code != 0 ? buf : "unknown error"));
}

struct EvpPkeyDeleter {
  void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using EvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* c) const noexcept { EVP_MD_CTX_free(c); }
};
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

}  // namespace tier::crypto::detail
