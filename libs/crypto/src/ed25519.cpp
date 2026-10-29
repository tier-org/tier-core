#include "tier/crypto/ed25519.hpp"

#include <cstddef>
#include <vector>

#include "wolf_backend.hpp"

namespace tier::crypto {
namespace {

// Load the full keypair (seed + public key) into a wolfSSL key so it can sign.
void import_keypair(detail::Ed25519Key& key, const Ed25519Seed& seed,
                    const Ed25519PublicKey& pub) {
  const int rc = wc_ed25519_import_private_key(
      seed.data(), static_cast<word32>(seed.size()),
      pub.data(), static_cast<word32>(pub.size()), key.get());
  if (rc != 0) {
    detail::throw_wolf("wc_ed25519_import_private_key", rc);
  }
}

}  // namespace

Ed25519Verifier::Ed25519Verifier(const Ed25519PublicKey& public_key) noexcept
    : public_key_(public_key) {}

bool Ed25519Verifier::verify(ByteSpan message, ByteSpan signature) const {
  if (signature.size() != kEd25519SignatureSize) {
    return false;
  }
  detail::Ed25519Key key;
  if (wc_ed25519_import_public(public_key_.data(),
                               static_cast<word32>(public_key_.size()),
                               key.get()) != 0) {
    return false;
  }
  int result = 0;
  const int rc = wc_ed25519_verify_msg(
      signature.data(), static_cast<word32>(signature.size()),
      message.data(), static_cast<word32>(message.size()), &result, key.get());
  return rc == 0 && result == 1;
}

Ed25519Signer::Ed25519Signer(const Ed25519Seed& seed,
                             const Ed25519PublicKey& public_key) noexcept
    : seed_(seed), public_key_(public_key) {}

std::vector<Byte> Ed25519Signer::sign(ByteSpan message) const {
  detail::Ed25519Key key;
  import_keypair(key, seed_, public_key_);

  std::vector<Byte> signature(kEd25519SignatureSize);
  auto signature_len = static_cast<word32>(signature.size());
  const int rc = wc_ed25519_sign_msg(message.data(),
                                     static_cast<word32>(message.size()),
                                     signature.data(), &signature_len, key.get());
  if (rc != 0) {
    detail::throw_wolf("wc_ed25519_sign_msg", rc);
  }
  signature.resize(signature_len);
  return signature;
}

std::vector<Byte> Ed25519Signer::public_key() const {
  return std::vector<Byte>(public_key_.begin(), public_key_.end());
}

}  // namespace tier::crypto
