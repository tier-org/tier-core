#include <cstdio>
#include <vector>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

}  // namespace

int main() {
  using namespace tier::crypto;

  const NodeIdentity id = NodeIdentity::generate();
  check(id.public_key().size() == kEd25519PublicKeySize, "public key size");

  bool nonzero = false;
  for (const Byte b : id.public_key()) {
    nonzero = nonzero || (b != 0);
  }
  check(nonzero, "public key is not all-zero");

  // Sign / verify round-trip.
  const std::vector<Byte> message{0x74, 0x69, 0x65, 0x72, 0x00, 0x01, 0x02, 0x03};
  const std::vector<Byte> signature = id.signer().sign(message);
  check(signature.size() == kEd25519SignatureSize, "signature size");

  const Ed25519Verifier verifier(id.public_key());
  check(verifier.verify(message, signature), "verify valid signature");

  // A flipped signature byte must be rejected.
  std::vector<Byte> tampered_sig = signature;
  tampered_sig[0] = static_cast<Byte>(tampered_sig[0] ^ 0xFFu);
  check(!verifier.verify(message, tampered_sig), "reject tampered signature");

  // A different message must be rejected.
  std::vector<Byte> other_message = message;
  other_message[0] = static_cast<Byte>(other_message[0] ^ 0xFFu);
  check(!verifier.verify(other_message, signature), "reject wrong message");

  // Persistence: from_seed reproduces the same identity and signs verifiably.
  const NodeIdentity restored = NodeIdentity::from_seed(id.seed());
  check(restored.public_key() == id.public_key(), "from_seed reproduces public key");
  const std::vector<Byte> restored_sig = restored.signer().sign(message);
  check(verifier.verify(message, restored_sig), "restored identity signs verifiably");

  // Self-signed certificate: non-empty DER beginning with a SEQUENCE tag.
  const std::vector<Byte> certificate = id.self_signed_certificate_der();
  check(!certificate.empty(), "certificate is non-empty");
  check(!certificate.empty() && certificate[0] == 0x30, "certificate is a DER SEQUENCE");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
