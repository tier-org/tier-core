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
};

// Bumped to 2 when the embedded membership record grew a version field, and to 3
// when the peers response grew the node's own network. tierctl and tierd ship
// together in one package, so the admin plane need not stay compatible across
// versions, but the bump makes a mismatched pair fail cleanly.
inline constexpr std::uint8_t kAdminVersion = 3;

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

// request: [version:1][op:1]
std::vector<std::uint8_t> encode_admin_request(AdminOp op);
std::optional<AdminOp> decode_admin_request(std::span<const std::uint8_t> in);

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
