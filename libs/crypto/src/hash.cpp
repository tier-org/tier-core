#include "tier/crypto/hash.hpp"

#include <stdexcept>
#include <string>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

namespace tier::crypto {

Digest256 sha256(ByteSpan data) {
  Digest256 out{};
  wc_Sha256 sha;
  int rc = wc_InitSha256(&sha);
  if (rc == 0) {
    rc = wc_Sha256Update(&sha, data.data(), static_cast<word32>(data.size()));
  }
  if (rc == 0) {
    rc = wc_Sha256Final(&sha, out.data());
  }
  wc_Sha256Free(&sha);
  if (rc != 0) {
    throw std::runtime_error("wolfSSL SHA-256 failed: " + std::to_string(rc));
  }
  return out;
}

}  // namespace tier::crypto
