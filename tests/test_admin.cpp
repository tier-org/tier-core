#include <cstdio>
#include <vector>

#include "tier/core/admin.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::PeerInfo peer(std::uint8_t tag, tier::core::RoleSet roles,
                          tier::core::Liveness liveness,
                          std::vector<std::string> addresses) {
  tier::core::PeerInfo info;
  info.id.fill(tag);
  info.roles = roles;
  info.incarnation = tag;
  info.liveness = liveness;
  info.addresses = std::move(addresses);
  return info;
}

}  // namespace

int main() {
  using tier::core::AdminOp;
  using tier::core::Liveness;
  using tier::core::Role;

  // Request round-trip and rejection of a bad version / op / trailing byte.
  {
    const auto req = tier::core::encode_admin_request(AdminOp::peers);
    const auto op = tier::core::decode_admin_request(req);
    check(op.has_value() && *op == AdminOp::peers, "request round-trips");

    check(!tier::core::decode_admin_request({}).has_value(), "empty request rejected");
    std::vector<std::uint8_t> bad_ver{0x02, 0x01};
    check(!tier::core::decode_admin_request(bad_ver).has_value(),
          "wrong version rejected");
    std::vector<std::uint8_t> bad_op{tier::core::kAdminVersion, 0x7F};
    check(!tier::core::decode_admin_request(bad_op).has_value(), "unknown op rejected");
    auto trailing = req;
    trailing.push_back(0x00);
    check(!tier::core::decode_admin_request(trailing).has_value(),
          "trailing byte in request rejected");
  }

  // Peers response round-trip: three peers, a two-member connected subset.
  std::vector<tier::core::PeerInfo> peers;
  peers.push_back(peer(0x01, tier::core::role_bit(Role::validator) |
                                 tier::core::role_bit(Role::keeper),
                       Liveness::alive, {"1.2.3.4:7777", "[2001:db8::1]:7777"}));
  peers.push_back(peer(0x02, tier::core::role_bit(Role::client), Liveness::suspect,
                       {}));
  peers.push_back(peer(0x03, tier::core::role_bit(Role::transmitter),
                       Liveness::dead, {"[2001:db8::3]:7777"}));

  std::vector<tier::core::PeerId> connected;
  connected.push_back(peers[0].id);
  connected.push_back(peers[2].id);

  const auto encoded = tier::core::encode_admin_peers(peers, connected);
  const auto decoded = tier::core::decode_admin_peers(encoded);
  check(decoded.has_value(), "peers response decodes");
  check(decoded && decoded->size() == peers.size(), "peer count round-trips");
  if (decoded && decoded->size() == peers.size()) {
    for (std::size_t i = 0; i < peers.size(); ++i) {
      check((*decoded)[i].info.id == peers[i].id, "id round-trips");
      check((*decoded)[i].info.roles == peers[i].roles, "roles round-trip");
      check((*decoded)[i].info.liveness == peers[i].liveness, "liveness round-trips");
      check((*decoded)[i].info.addresses == peers[i].addresses, "addresses round-trip");
    }
    check((*decoded)[0].connected, "peer 1 reported connected");
    check(!(*decoded)[1].connected, "peer 2 reported not connected");
    check((*decoded)[2].connected, "peer 3 reported connected");
  }

  // A trailing byte is rejected.
  {
    auto trailing = encoded;
    trailing.push_back(0xAA);
    check(!tier::core::decode_admin_peers(trailing).has_value(),
          "trailing byte in response rejected");
  }

  // Every truncation is rejected without crashing.
  {
    bool all_rejected = true;
    for (std::size_t n = 0; n < encoded.size(); ++n) {
      std::vector<std::uint8_t> prefix(encoded.begin(),
                                       encoded.begin() + static_cast<long>(n));
      if (tier::core::decode_admin_peers(prefix).has_value()) {
        all_rejected = false;
        break;
      }
    }
    check(all_rejected, "every truncation of the response is rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
