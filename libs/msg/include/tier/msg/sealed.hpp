#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/kem.hpp"
#include "tier/crypto/kx.hpp"
#include "tier/crypto/primitives.hpp"

// End-to-end encrypted application messages between network participants.
//
// A message is sealed to a recipient's published encryption public keys and
// signed by the sender's Ed25519 identity key, so the recipient has both
// confidentiality (only it can decrypt) and sender authenticity (it knows who
// sent it, and that nothing was altered). Three cipher suites are offered; the
// sender picks one per message and tags it in the envelope:
//
//   classical  X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305
//   hybrid     X25519 + ML-KEM-768 (both secrets into HKDF) -> ChaCha20-Poly1305
//   pq         ML-KEM-768 -> HKDF-SHA256 -> ChaCha20-Poly1305
//
// Hybrid is the recommended default: it stays secure if either X25519 or
// ML-KEM is later broken. Classical interoperates with peers without PQ; pq is
// for a fully post-quantum posture.
//
// The recipient's encryption keys are learned from a signed `enc_keys` announce
// exchanged on connect (make/open_enc_keys_announce), not from gossip, so the
// large ML-KEM key does not bloat the membership table.
namespace tier::msg {

using Byte = tier::crypto::Byte;
using ByteSpan = tier::crypto::ByteSpan;

enum class Suite : std::uint8_t {
  classical = 1,
  hybrid = 2,
  pq = 3,
};

// True for a value that names a defined suite.
[[nodiscard]] bool is_known_suite(std::uint8_t v) noexcept;

// A peer's long-term encryption public keys, as carried in its enc_keys
// announce. Both are always present; a classical-only or pq-only message uses
// just the one it needs.
struct PeerEncKeys {
  tier::crypto::X25519PublicKey x25519{};
  tier::crypto::MlKem768PublicKey mlkem{};
};

// --- encryption-key announce ----------------------------------------------

// Build this node's owner-signed enc_keys announce (a control message starting
// with the enc_keys type tag). Binds the network name so an announce cannot be
// replayed into another network. Throws only on a backend failure.
[[nodiscard]] std::vector<Byte> make_enc_keys_announce(
    const tier::crypto::NodeIdentity& self, std::string_view network);

// Decode and verify a peer's enc_keys announce against the Ed25519 identity key
// the peer authenticated with on the connection. Returns the peer's encryption
// keys, or std::nullopt on any malformed input or a signature that does not
// verify (untrusted bytes: never crashes, never trusts a length).
[[nodiscard]] std::optional<PeerEncKeys> open_enc_keys_announce(
    std::string_view network, const tier::crypto::Ed25519PublicKey& sender_identity,
    ByteSpan message);

// --- sealed application message --------------------------------------------

// The recipient of a sealed message: its id plus the encryption public keys the
// sender seals to.
struct Recipient {
  tier::core::PeerId id{};
  PeerEncKeys keys{};
};

// Seal `plaintext` to `recipient` under `suite`, signed by `sender`. Returns the
// full control message (starting with the app_sealed type tag) ready to send.
// `plaintext` must be small enough that the whole envelope fits one transport
// frame (see kMaxSealedPlaintext); throws std::length_error otherwise and
// std::runtime_error on a backend failure.
[[nodiscard]] std::vector<Byte> seal(const tier::crypto::NodeIdentity& sender,
                                     std::string_view network, Suite suite,
                                     const Recipient& recipient,
                                     ByteSpan plaintext);

// Largest plaintext that always fits a single transport frame once sealed, for
// the heaviest suite (hybrid, which carries the 1088-byte ML-KEM ciphertext).
inline constexpr std::size_t kMaxSealedPlaintext = 60000;

struct Opened {
  tier::core::PeerId sender_id{};  // authenticated: matches the signing key
  Suite suite{};
  std::vector<Byte> plaintext;
};

// Open a sealed message addressed to `recipient`. `sender_identity` is the
// Ed25519 identity key of the connection the message arrived on; the envelope's
// claimed sender id must hash to it and its signature must verify under it.
// Returns the plaintext and authenticated sender id, or std::nullopt if the
// message is malformed, is not addressed to us, fails signature verification,
// or fails to decrypt. Never throws on attacker-controlled input.
[[nodiscard]] std::optional<Opened> open(
    const tier::crypto::NodeIdentity& recipient, std::string_view network,
    const tier::crypto::Ed25519PublicKey& sender_identity, ByteSpan message);

}  // namespace tier::msg
