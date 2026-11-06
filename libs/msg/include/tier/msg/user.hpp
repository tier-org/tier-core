#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"

// User identity over device identity (see docs/multi-identity.md).
//
// A user identity is an Ed25519 keypair independent of any device. The user key
// signs a device credential authorizing a device (by its PeerId) to act for the
// user, and that credential travels inside each message in a user envelope. The
// device identity still does all the encryption and transport (tier::msg sealed,
// M1); this layer only adds user-level authentication and addressing on top, no
// new encryption.
namespace tier::msg {

using Byte = tier::crypto::Byte;
using ByteSpan = tier::crypto::ByteSpan;

// A user id is the hash of the user's Ed25519 public key, same shape as a PeerId.
[[nodiscard]] tier::core::PeerId user_id_of(
    const tier::crypto::Ed25519PublicKey& user_pub);

// Mint a device credential: the user key authorizes `device_id` until
// `expiry_unix`, bound to `network`. The returned blob carries the expiry and
// the signature; store it on the device and send it in every user envelope.
// Throws only on a backend failure.
[[nodiscard]] std::vector<Byte> make_device_credential(
    const tier::crypto::NodeIdentity& user, std::string_view network,
    const tier::core::PeerId& device_id, std::uint64_t expiry_unix);

// Verify a device credential: that `user_pub` signed an authorization of
// `device_id` for `network`, and that it has not expired at `now_unix`. Never
// throws on attacker input.
[[nodiscard]] bool verify_device_credential(
    std::string_view network, const tier::crypto::Ed25519PublicKey& user_pub,
    const tier::core::PeerId& device_id, std::uint64_t now_unix,
    ByteSpan credential);

// Assemble the user envelope that travels as the transport plaintext: the
// sender's user public key, its device credential, the recipient user id (which
// local user the receiving device must route this to, since one device may host
// many users), and the inner payload.
[[nodiscard]] std::vector<Byte> make_user_envelope(
    const tier::crypto::Ed25519PublicKey& sender_user_pub, ByteSpan credential,
    const tier::core::PeerId& recipient_user_id, ByteSpan inner_plaintext);

// A user envelope opened and authenticated.
struct OpenedUser {
  tier::core::PeerId sender_user_id{};     // authenticated via the credential chain
  tier::core::PeerId recipient_user_id{};  // which local user this is addressed to
  std::vector<Byte> plaintext;
};

// Parse and authenticate a user envelope. `sender_device` is the device id the
// transport already authenticated (the id of the connection the message arrived
// on). Returns the sender's user id, the recipient user id, and the inner
// payload only if the embedded credential proves `sender_device` is authorized
// by the envelope's user key for `network` and is unexpired at `now_unix`;
// std::nullopt otherwise. Never throws.
[[nodiscard]] std::optional<OpenedUser> open_user_envelope(
    std::string_view network, const tier::core::PeerId& sender_device,
    std::uint64_t now_unix, ByteSpan envelope);

// --- user directory control messages (see docs/multi-identity.md) ----------
// These are the user_register / user_lookup / user_result control frames. The
// device id is never a field: a communicator reads it from the authenticated
// connection and verifies the carried credential against it, so an enrollment
// cannot claim a device id it does not control.

// A device enrolls under its user. Carries the user key and the device
// credential (verified by the communicator against the connection); issued_unix
// is a monotonic refresh stamp and expiry_unix the directory TTL.
[[nodiscard]] std::vector<Byte> make_user_register(
    const tier::crypto::Ed25519PublicKey& user_pub, ByteSpan credential,
    std::uint64_t issued_unix, std::uint64_t expiry_unix);

struct UserRegister {
  tier::crypto::Ed25519PublicKey user_pub{};
  std::vector<Byte> credential;
  std::uint64_t issued_unix{};
  std::uint64_t expiry_unix{};
};

// Parse a user_register frame (structural only; the caller must still verify the
// credential against the connection's device id with verify_device_credential).
[[nodiscard]] std::optional<UserRegister> open_user_register(ByteSpan message);

// Resolve a user id to its enrolled device ids.
[[nodiscard]] std::vector<Byte> make_user_lookup(const tier::core::PeerId& user_id);
[[nodiscard]] std::optional<tier::core::PeerId> open_user_lookup(ByteSpan message);

// The set of currently-enrolled device ids for a user.
[[nodiscard]] std::vector<Byte> make_user_result(
    const tier::core::PeerId& queried_user,
    const std::vector<tier::core::PeerId>& device_ids);

struct UserResult {
  tier::core::PeerId user_id{};
  std::vector<tier::core::PeerId> device_ids;
};

// Parse a user_result frame; its user id must equal `expected`. std::nullopt on
// malformed input or a mismatched id.
[[nodiscard]] std::optional<UserResult> open_user_result(
    const tier::core::PeerId& expected, ByteSpan message);

}  // namespace tier::msg
