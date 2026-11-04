#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"
#include "tier/msg/sealed.hpp"

// Client-to-client discovery (see docs/communicator.md).
//
// A plain client is never dialed and is not gossiped, so two clients cannot find
// each other. To be reachable, a client publishes an owner-signed presence
// record - its addresses and encryption keys - to the communicator(s)
// responsible for its id (rendezvous hashing). Another node resolves it by
// asking the same communicator, then connects directly.
//
// A presence record is relayed (A learns B's record from a communicator, not
// over a direct connection to B), so unlike an enc_keys announce it must carry
// B's Ed25519 identity key: the resolver checks that the key hashes to the
// claimed id and that the signature verifies under it. Nothing in a record is
// trusted on the communicator's say-so.
namespace tier::msg {

// An owner-signed statement of where a node can be reached and the keys to seal
// to it. `record_bytes` is the exact canonical encoding the signature covers
// (everything after the control type tag); the registry stores and re-emits
// these bytes verbatim so a relayed record is never re-encoded.
struct PresenceRecord {
  tier::core::PeerId id{};
  tier::crypto::Ed25519PublicKey identity_key{};
  tier::core::RoleSet roles{};
  // Monotonic issue stamp (unix seconds when the record was signed). Lets a
  // registry accept a refresh and reject a replay of an older record; distinct
  // from the node's membership incarnation.
  std::uint64_t issued_unix{};
  std::uint64_t expiry_unix{};
  PeerEncKeys enc_keys{};
  std::vector<std::string> addresses;
  std::vector<Byte> record_bytes;  // canonical signed encoding (no type tag)
};

// Build this node's owner-signed presence_register control message (starts with
// the presence_register type tag). Addresses over the per-peer / length bounds
// are clamped before signing. Binds the network name. Throws only on a backend
// failure.
[[nodiscard]] std::vector<Byte> make_presence_register(
    const tier::crypto::NodeIdentity& self, std::string_view network,
    tier::core::RoleSet roles, const std::vector<std::string>& addresses,
    std::uint64_t issued_unix, std::uint64_t expiry_unix);

// Parse and verify a presence_register message (used by a communicator). Checks
// id == sha256(identity_key) and the signature over the transcript bound to
// `network`. Returns the record (with record_bytes set), or std::nullopt on any
// malformed input or bad signature. Never throws on attacker input.
[[nodiscard]] std::optional<PresenceRecord> open_presence_register(
    std::string_view network, ByteSpan message);

// Build a presence_lookup message asking a communicator to resolve `target`.
[[nodiscard]] std::vector<Byte> make_presence_lookup(
    const tier::core::PeerId& target);

// Parse a presence_lookup message. Returns the target id or std::nullopt.
[[nodiscard]] std::optional<tier::core::PeerId> open_presence_lookup(
    ByteSpan message);

// Build a presence_result message for `queried`. If `record_bytes` is empty the
// result is "not found"; otherwise it carries the stored canonical record bytes
// verbatim (as produced by a prior open_presence_register().record_bytes).
[[nodiscard]] std::vector<Byte> make_presence_result(
    const tier::core::PeerId& queried, ByteSpan record_bytes);

// Parse and verify a presence_result (used by the resolver). The outer optional
// is std::nullopt on malformed input; the inner optional is std::nullopt when
// the communicator reported not-found. A present record is fully verified the
// same way as open_presence_register, and its id must equal `expected`.
[[nodiscard]] std::optional<std::optional<PresenceRecord>> open_presence_result(
    std::string_view network, const tier::core::PeerId& expected,
    ByteSpan message);

}  // namespace tier::msg
