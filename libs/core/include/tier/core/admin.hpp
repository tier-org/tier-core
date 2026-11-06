#pragma once

#include <array>
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
  peers = 1,        // dump the known-peers table and which of them are connected
  send = 2,         // send an end-to-end encrypted message to a peer (device id)
  inbox = 3,        // drain and return messages received since the last inbox call
  id = 4,           // report this node's own device id
  user_add = 6,     // host a user identity on the node (optionally from a seed)
  user_list = 7,    // list the user ids hosted on the node
  user_remove = 8,  // stop hosting a user identity
  send_as = 9,      // send from a local user to a user id (fans out to devices)
};

// Bumped to 2 when the embedded membership record grew a version field, to 3
// when the peers response grew the node's own network, to 4 when the send and
// inbox ops were added, to 5 when the id op was added, to 6 when multi-identity
// first arrived (a single boot-time user), and to 7 when user identities became
// runtime-managed: the user_add / user_list / user_remove ops, send_as (send
// from a chosen local user to a user), the recipient user id in inbox messages,
// and the id reply carrying the device id only (users are listed separately).
// tierctl and tierd ship together in one package, so the admin plane need not
// stay compatible across versions, but the bump makes a mismatched pair fail
// cleanly.
inline constexpr std::uint8_t kAdminVersion = 7;

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

// A decoded admin request. For `peers`, `inbox`, `id` and `user_list` only `op`
// is set. `send` puts the recipient device id in `recipient`. `send_as` puts the
// sending local user in `from_user` and the recipient user in `recipient`, plus
// `suite`/`plaintext`. `user_remove` puts the user id in `recipient`. `user_add`
// sets `has_seed`/`seed` (a 32-byte Ed25519 seed to import, else generate).
struct AdminRequest {
  AdminOp op{};
  PeerId recipient{};   // device id (send), recipient user (send_as), user (user_remove)
  PeerId from_user{};   // sending local user (send_as)
  std::uint8_t suite = 0;
  std::vector<std::uint8_t> plaintext;
  bool has_seed = false;              // user_add: a seed was supplied to import
  std::array<std::uint8_t, 32> seed{};  // user_add: the imported seed
};

// request (peers/inbox/id/user_list): [version:1][op:1]
std::vector<std::uint8_t> encode_admin_request(AdminOp op);

// request (send): [version:1][op:2][recipient:32][suite:1][len:4 BE][plaintext]
std::vector<std::uint8_t> encode_admin_send(const PeerId& recipient,
                                            std::uint8_t suite,
                                            std::span<const std::uint8_t> plaintext);

// request (send_as):
//   [version:1][op:9][from_user:32][to_user:32][suite:1][len:4 BE][plaintext]
std::vector<std::uint8_t> encode_admin_send_as(const PeerId& from_user,
                                               const PeerId& to_user,
                                               std::uint8_t suite,
                                               std::span<const std::uint8_t> plaintext);

// request (user_add): [version:1][op:6][has_seed:1][seed:32?]
std::vector<std::uint8_t> encode_admin_user_add(
    std::optional<std::array<std::uint8_t, 32>> seed);

// request (user_remove): [version:1][op:8][user_id:32]
std::vector<std::uint8_t> encode_admin_user_remove(const PeerId& user_id);

// Decode any admin request. std::nullopt on a wrong version, unknown op,
// oversize plaintext (> kMaxAdminMessageBytes) or trailing bytes.
std::optional<AdminRequest> decode_admin_request(std::span<const std::uint8_t> in);

// send response (shared by send and send_as): [version:1][op][status:1]
// (status 0 = accepted - sent or queued, 1 = failed). `op` echoes the request.
std::vector<std::uint8_t> encode_admin_send_reply(bool ok);
std::optional<bool> decode_admin_send_reply(std::span<const std::uint8_t> in);
std::vector<std::uint8_t> encode_admin_send_as_reply(bool ok);
std::optional<bool> decode_admin_send_as_reply(std::span<const std::uint8_t> in);

// user_add response: [version:1][op:6][status:1][user_id:32] (user id zeroed on
// failure). user_remove response: [version:1][op:8][existed:1].
struct AdminUserAddReply {
  bool ok = false;
  PeerId user_id{};
};
std::vector<std::uint8_t> encode_admin_user_add_reply(const AdminUserAddReply& r);
std::optional<AdminUserAddReply> decode_admin_user_add_reply(
    std::span<const std::uint8_t> in);
std::vector<std::uint8_t> encode_admin_user_remove_reply(bool existed);
std::optional<bool> decode_admin_user_remove_reply(std::span<const std::uint8_t> in);

// user_list response: [version:1][op:7][count:2 BE][user_id:32]*
std::vector<std::uint8_t> encode_admin_user_list(const std::vector<PeerId>& users);
std::optional<std::vector<PeerId>> decode_admin_user_list(
    std::span<const std::uint8_t> in);

// The node's own device id.
struct AdminId {
  PeerId device_id{};
};

// id response: [version:1][op:4][device_id:32]
std::vector<std::uint8_t> encode_admin_id_reply(const AdminId& id);
std::optional<AdminId> decode_admin_id_reply(std::span<const std::uint8_t> in);

// One received message as the inbox reports it. `sender_user` is set when the
// message was a user message that authenticated the sending user; `recipient_user`
// names which local user it was addressed to (both unset for a node message).
struct AdminInboxMessage {
  PeerId sender{};
  std::optional<PeerId> sender_user;
  std::optional<PeerId> recipient_user;
  std::uint8_t suite = 0;
  std::vector<std::uint8_t> plaintext;
};

// inbox response:
//   [version:1][op:3][count:2 BE]
//   ( [sender:32][has_user:1][user:32?][has_rcpt:1][rcpt:32?]
//     [suite:1][len:4 BE][plaintext] )*
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
