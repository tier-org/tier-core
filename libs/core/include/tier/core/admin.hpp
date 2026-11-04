#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"

namespace tier::core {

// Local admin/diagnostics protocol, spoken over a Unix socket between the
// daemon and the tierctl CLI. One request, one response, then the connection
// closes. The wire is the project's bounded binary codec (same discipline as
// the node-to-node control plane), not HTTP or JSON: tiny and cheap to produce
// and parse. The response decoders still treat their input as untrusted and
// never crash, never trust a length, and reject trailing bytes.
enum class AdminOp : std::uint8_t {
  peers = 1,  // dump the known-peers table and which of them are connected
  send = 2,   // send an end-to-end encrypted message to a peer
  inbox = 3,  // drain and return messages received since the last inbox call
};

// Bumped to 2 when the embedded membership record grew a version field, to 3
// when the peers response grew the node's own network, and to 4 when the send
// and inbox ops were added. tierctl and tierd ship together in one package, so
// the admin plane need not stay compatible across versions, but the bump makes
// a mismatched pair fail cleanly.
inline constexpr std::uint8_t kAdminVersion = 4;

// Largest application-message plaintext accepted over the admin socket. Ample
// for text messages; a node-to-node sealed message can be larger (up to the
// transport frame budget), but the local admin path caps it so a client cannot
// make the daemon buffer without bound.
inline constexpr std::size_t kMaxAdminMessageBytes = 16384;

// A peer as the admin plane reports it: its membership record plus whether the
// daemon currently holds a live connection to it (known vs connected).
struct AdminPeer {
  PeerInfo info;
  bool connected = false;
};

// The peers response decoded: the daemon's own network (the cluster it joined,
// a node-wide property not carried per peer) and its known-peers table.
struct AdminPeersReply {
  std::string network;
  std::vector<AdminPeer> peers;
};

// A decoded admin request. For `peers` and `inbox` only `op` is set; for `send`
// the recipient id, suite byte and plaintext are populated.
struct AdminRequest {
  AdminOp op{};
  PeerId recipient{};
  std::uint8_t suite = 0;
  std::vector<std::uint8_t> plaintext;
};

// request (peers/inbox): [version:1][op:1]
std::vector<std::uint8_t> encode_admin_request(AdminOp op);

// request (send): [version:1][op:2][recipient:32][suite:1][len:4 BE][plaintext]
std::vector<std::uint8_t> encode_admin_send(const PeerId& recipient,
                                            std::uint8_t suite,
                                            std::span<const std::uint8_t> plaintext);

// Decode any admin request. std::nullopt on a wrong version, unknown op,
// oversize plaintext (> kMaxAdminMessageBytes) or trailing bytes.
std::optional<AdminRequest> decode_admin_request(std::span<const std::uint8_t> in);

// send response: [version:1][op:2][status:1] (status 0 = sent, 1 = failed:
// peer not connected or its keys unknown).
std::vector<std::uint8_t> encode_admin_send_reply(bool ok);
std::optional<bool> decode_admin_send_reply(std::span<const std::uint8_t> in);

// One received message as the inbox reports it.
struct AdminInboxMessage {
  PeerId sender{};
  std::uint8_t suite = 0;
  std::vector<std::uint8_t> plaintext;
};

// inbox response:
//   [version:1][op:3][count:2 BE]( [sender:32][suite:1][len:4 BE][plaintext] )*
std::vector<std::uint8_t> encode_admin_inbox(
    const std::vector<AdminInboxMessage>& messages);
std::optional<std::vector<AdminInboxMessage>> decode_admin_inbox(
    std::span<const std::uint8_t> in);

// peers response:
//   [version:1][op:1=peers][net_len:1][network][membership_len:4 BE]
//   [membership-message][connected_count:2 BE][id:32]*
// The membership-message is encode_membership_message(peers); the id list names
// the connected subset. Decoding joins the two into AdminPeer{info, connected}
// and returns them with the network.
std::vector<std::uint8_t> encode_admin_peers(
    std::string_view network, const std::vector<PeerInfo>& peers,
    const std::vector<PeerId>& connected);
std::optional<AdminPeersReply> decode_admin_peers(
    std::span<const std::uint8_t> in);

}  // namespace tier::core
