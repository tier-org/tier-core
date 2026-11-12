#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"

namespace tier::core {

// Control-plane (node-to-node) message types.
//   membership    - an anti-entropy snapshot of the known-peers table.
//   ping/ack      - SWIM direct liveness probe and its reply.
//   ping_req      - SWIM indirect probe: "ping this target for me and relay its ack".
//   observed_addr - "this is the ip:port I saw your connection come from"; the
//                   receiver uses it to learn its own externally reachable
//                   address (it binds a wildcard and cannot know this itself).
enum class ControlType : std::uint8_t {
  membership = 1,
  ping = 2,
  ack = 3,
  ping_req = 4,
  observed_addr = 5,
  // enc_keys      - an owner-signed announcement of this node's encryption
  //                 public keys (X25519 + ML-KEM-768), sent on handshake so a
  //                 peer can send it end-to-end encrypted messages. The codec
  //                 and crypto live in tier::msg; only the type tag is here.
  // app_sealed    - an end-to-end encrypted application message (see tier::msg).
  enc_keys = 6,
  app_sealed = 7,
  // Client-to-client discovery via a communicator (see docs/communicator.md).
  // Like enc_keys/app_sealed, the payload codec and crypto live in tier::msg;
  // only the type tags are here.
  //   presence_register - a client registers its owner-signed presence record
  //                       (addresses + enc_keys) with a communicator.
  //   presence_lookup   - a node asks a communicator to resolve a target id.
  //   presence_result   - a communicator returns the stored record (or a
  //                       not-found marker).
  presence_register = 8,
  presence_lookup = 9,
  presence_result = 10,
  // User directory for multi-identity (see docs/multi-identity.md). Same
  // pattern: payload codec and crypto in tier::msg, only the tags here.
  //   user_register - a device enrolls under a user id (carries the user key and
  //                   the device credential); the communicator aggregates.
  //   user_lookup   - resolve a user id to its enrolled device ids.
  //   user_result   - the set of currently-enrolled device ids for a user.
  user_register = 11,
  user_lookup = 12,
  user_result = 13,
  // NAT hole punching (see docs/communicator.md, M-NAT). Payload codec in
  // tier::msg, tags here.
  //   hole_punch_request - client -> communicator: coordinate a punch to a
  //                        target, carrying my candidate addresses.
  //   hole_punch_signal  - communicator -> client: a relayed punch request from
  //                        an origin, carrying the origin's candidate addresses.
  hole_punch_request = 14,
  hole_punch_signal = 15,
  // user_deregister - a device removes its own enrollment under a user id from
  // the responsible communicator (presence: the device's last subscriber went
  // away, so the user is no longer online). Same body and credential check as
  // user_register; the communicator drops the (user, device) directory entry.
  user_deregister = 16,
};

// Peek the control type of a received message without decoding it. Returns
// std::nullopt on an empty message or an unknown type byte.
std::optional<ControlType> peek_control_type(std::span<const std::uint8_t> in);

// Owner public key carried with each membership record: a 32-byte Ed25519 key.
// The owner's id is SHA-256 of this key, so a verifier recomputes the id and
// rejects a record whose key does not hash to its claimed id.
inline constexpr std::uint8_t kPublicKeyLen = 32;
// Upper bound on the signature length byte. Ed25519 is 64 bytes; the extra room
// leaves space without forcing a wire change the day a larger scheme is added
// (a post-quantum signature will need this and the message budget revisited).
inline constexpr std::uint8_t kMaxSignatureLen = 128;
// Target cap on one membership message. Kept below the transport frame limit
// (tier::net framing rejects frames over 65536 bytes) with margin, so a split
// snapshot always fits a single frame. A table larger than this is sent as
// several messages (see encode_membership_messages).
inline constexpr std::size_t kMaxMembershipMessageBytes = 60000;

// Encode a membership snapshot as a control message:
//   [type:1][count:4 BE]( [id:32][pubkey:32][sig_len:1][sig:sig_len]
//                          [role:1][incarnation:8 BE][liveness:1]
//                          [addr_count:1]( [addr_len:2 BE][addr:addr_len] )*
//                          [ver_len:1][ver:ver_len] )*
// `pubkey` is the owner's Ed25519 public key and `sig` its signature over the
// owner-asserted fields (see membership_signing_payload). The signature is not
// checked here - the codec only moves bytes; the network layer verifies it
// against the owner's id before trusting a record (owner-signed membership).
std::vector<std::uint8_t> encode_membership_message(
    const std::vector<PeerInfo>& peers);

// Encode a snapshot as one or more membership messages, each no larger than
// `max_bytes`, so a table too big for a single transport frame is split into
// self-contained, individually valid messages a peer merges incrementally. Each
// returned message decodes on its own; peers are packed greedily and never
// split across messages. The caller sends each in its own frame.
std::vector<std::vector<std::uint8_t>> encode_membership_messages(
    const std::vector<PeerInfo>& peers,
    std::size_t max_bytes = kMaxMembershipMessageBytes);

// The canonical byte string an owner signs to authenticate its own membership
// record: a domain-separation tag, the network name, and the owner-asserted
// fields (id, public key, roles, incarnation, addresses, version). Liveness is
// deliberately excluded - it is a third-party SWIM assertion (suspect/dead) that
// any peer may make and the owner refutes by raising its incarnation, so it must
// not be bound by the owner's signature. Binding the network name stops a record
// signed for one network from being replayed into another.
std::vector<std::uint8_t> membership_signing_payload(std::string_view network,
                                                      const PeerInfo& peer);

// Decode a membership control message. Returns std::nullopt on any malformed or
// out-of-bounds input (this is a decoder of untrusted bytes; it must never
// crash and never trust a length). Trailing bytes are rejected. The signature is
// returned verbatim for the caller to verify; a decoded record is not yet
// trusted.
std::optional<std::vector<PeerInfo>> decode_membership_message(
    std::span<const std::uint8_t> in);

// --- SWIM probe messages ---------------------------------------------------
// ping/ack:  [type:1][seq:8 BE]
// ping_req:  [type:1][seq:8 BE][target:32]
// `seq` matches an ack to the probe that caused it; `target` names the peer the
// relay should ping on the requester's behalf.

struct PingMessage {
  std::uint64_t seq = 0;
};
struct AckMessage {
  std::uint64_t seq = 0;
};
struct PingReqMessage {
  std::uint64_t seq = 0;
  PeerId target{};
};

std::vector<std::uint8_t> encode_ping(std::uint64_t seq);
std::vector<std::uint8_t> encode_ack(std::uint64_t seq);
std::vector<std::uint8_t> encode_ping_req(std::uint64_t seq, const PeerId& target);

// Decoders of untrusted bytes: std::nullopt on any malformed input, no crash,
// trailing bytes rejected.
std::optional<PingMessage> decode_ping(std::span<const std::uint8_t> in);
std::optional<AckMessage> decode_ack(std::span<const std::uint8_t> in);
std::optional<PingReqMessage> decode_ping_req(std::span<const std::uint8_t> in);

// --- observed-address message ----------------------------------------------
// [type:1][addr_len:2 BE][addr:addr_len], addr_len <= kMaxAddressLen. The
// address is an "ip:port" string (IPv6 bracketed, "[::1]:443").

struct ObservedAddrMessage {
  std::string address;
};

std::vector<std::uint8_t> encode_observed_addr(std::string_view address);
std::optional<ObservedAddrMessage> decode_observed_addr(
    std::span<const std::uint8_t> in);

// Bounds (reject absurd inputs rather than allocate on an attacker's word).
inline constexpr std::uint32_t kMaxPeersPerMessage = 4096;
inline constexpr std::uint16_t kMaxAddressLen = 256;
// Addresses advertised per peer: enough for a handful of interfaces/families
// (IPv4 + IPv6, a couple of each), fits the single count byte on the wire.
inline constexpr std::uint8_t kMaxAddressesPerPeer = 8;
// Advertised version string ("major.minor.patch" plus optional pre-release/
// build suffix). Bounded so a hostile peer cannot inflate a message, and fits
// the single length byte on the wire.
inline constexpr std::uint8_t kMaxVersionLen = 64;

}  // namespace tier::core
