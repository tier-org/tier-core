#include "tier/crypto/hash.hpp"

#include <cstddef>
#include <stdexcept>

#include <openssl/evp.h>

namespace tier::crypto {

Digest256 sha256(ByteSpan data) {
  Digest256 out{};
  std::size_t out_len = out.size();
  if (EVP_Q_digest(nullptr, "SHA256", nullptr, data.data(), data.size(),
                   out.data(), &out_len) != 1 ||
      out_len != out.size()) {
    throw std::runtime_error("OpenSSL SHA-256 failed");
  }
  return out;
}

}  // namespace tier::crypto
