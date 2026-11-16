#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/primitives.hpp"

// Relay envelope (see docs/communicator.md, M-NAT). The fallback for when a
// direct connection and a hole punch both fail (symmetric NAT / CGNAT): the
// sender wraps an already-sealed application message and sends it to a
// responsible communicator, which forwards it verbatim to the target.
//
// The envelope carries the target id, the sender's Ed25519 public key, and the
// opaque sealed blob. The sender key is only a hint for the inner signature
// check: it is cryptographically bound (the sealed message's signature must
// verify under it and the claimed sender id must hash to it), so a malicious
// relay can neither forge a sender nor read the ciphertext.
namespace tier::msg {

using Byte = tier::crypto::Byte;
using ByteSpan = tier::crypto::ByteSpan;

// Build a relay frame: [type:1][dst:32][src_key:32][sealed...].
[[nodiscard]] std::vector<Byte> make_relay_frame(
    const tier::core::PeerId& dst,
    const tier::crypto::Ed25519PublicKey& src_key, ByteSpan sealed);

struct RelayFrame {
  tier::core::PeerId dst{};
  tier::crypto::Ed25519PublicKey src_key{};
  ByteSpan sealed;  // points into the decoded message; consume synchronously
};

// Parse a relay frame. Returns std::nullopt on a wrong tag or a frame too short
// to hold the fixed header. The sealed blob is whatever follows the header
// (possibly empty) and is not interpreted here.
[[nodiscard]] std::optional<RelayFrame> open_relay_frame(ByteSpan message);

}  // namespace tier::msg
