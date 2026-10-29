#pragma once

#include <vector>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/primitives.hpp"

namespace tier::crypto {

// A node's long-term identity: an Ed25519 keypair that is the node's stable
// network name, plus a self-signed X.509 certificate carrying that public key
// in its SubjectPublicKeyInfo (the libp2p-TLS pattern). The certificate becomes
// the QUIC/TLS leaf certificate, so a peer's identity is exactly the key it
// presents in the handshake -no external PKI.
class NodeIdentity {
 public:
  // Fresh identity from the system CSPRNG. Throws std::runtime_error on backend
  // failure.
  [[nodiscard]] static NodeIdentity generate();

  // Reconstruct from a persisted 32-byte Ed25519 seed. Throws
  // std::invalid_argument on wrong size, std::runtime_error on backend failure.
  [[nodiscard]] static NodeIdentity from_seed(ByteSpan seed);

  // The 32-byte secret seed, to persist. Handle as a secret.
  [[nodiscard]] const Ed25519Seed& seed() const noexcept { return signer_.seed(); }

  // The 32-byte Ed25519 public key = the node's identity material.
  [[nodiscard]] const Ed25519PublicKey& public_key() const noexcept {
    return signer_.public_key_bytes();
  }

  [[nodiscard]] const Ed25519Signer& signer() const noexcept { return signer_; }

  // DER-encoded self-signed X.509 certificate signed by this identity. Throws
  // std::runtime_error on backend failure.
  [[nodiscard]] std::vector<Byte> self_signed_certificate_der() const;

  // PKCS#8 DER encoding of the Ed25519 private key, for loading into the TLS
  // stack as the leaf key. Handle as a secret. Throws on backend failure.
  [[nodiscard]] std::vector<Byte> private_key_pkcs8_der() const;

 private:
  explicit NodeIdentity(Ed25519Signer signer) noexcept;

  Ed25519Signer signer_;
};

}  // namespace tier::crypto
