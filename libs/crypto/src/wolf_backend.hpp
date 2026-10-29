#pragma once

// Internal (non-installed) helpers over the wolfSSL C API: RAII wrappers and a
// uniform error path. Only translation units inside tier_crypto include this;
// wolfSSL types never cross into public headers.

#include <stdexcept>
#include <string>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

namespace tier::crypto::detail {

[[noreturn]] inline void throw_wolf(const char* what, int rc) {
  throw std::runtime_error(std::string(what) + " failed: " + std::to_string(rc));
}

// Owns a seeded wolfSSL CSPRNG.
class Rng {
 public:
  Rng() {
    const int rc = wc_InitRng(&rng_);
    if (rc != 0) {
      throw_wolf("wc_InitRng", rc);
    }
  }
  ~Rng() { wc_FreeRng(&rng_); }

  Rng(const Rng&) = delete;
  Rng& operator=(const Rng&) = delete;
  Rng(Rng&&) = delete;
  Rng& operator=(Rng&&) = delete;

  [[nodiscard]] WC_RNG* get() noexcept { return &rng_; }

 private:
  WC_RNG rng_{};
};

// Owns a wolfSSL ed25519_key.
class Ed25519Key {
 public:
  Ed25519Key() {
    const int rc = wc_ed25519_init(&key_);
    if (rc != 0) {
      throw_wolf("wc_ed25519_init", rc);
    }
  }
  ~Ed25519Key() { wc_ed25519_free(&key_); }

  Ed25519Key(const Ed25519Key&) = delete;
  Ed25519Key& operator=(const Ed25519Key&) = delete;
  Ed25519Key(Ed25519Key&&) = delete;
  Ed25519Key& operator=(Ed25519Key&&) = delete;

  [[nodiscard]] ed25519_key* get() noexcept { return &key_; }

 private:
  ed25519_key key_{};
};

}  // namespace tier::crypto::detail
