#include <algorithm>
#include <cstdio>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/net/node.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::net::Node make_node(tier::core::Role role) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(role), "127.0.0.1", 0);
}

bool connected_to(const tier::net::Node& n, const tier::core::PeerId& id) {
  const auto peers = n.connected_peers();
  return std::find(peers.begin(), peers.end(), id) != peers.end();
}

}  // namespace

int main() {
  using tier::core::Role;

  // Role-based topology (docs/topology.md). A and B are infrastructure
  // (backbone); E1 and E2 are edge clients. Everyone bootstraps through the hub
  // A, so every node learns every other's dialable address by gossip. The
  // asymmetry under test:
  //   - two edge clients NEVER form a direct connection, even knowing each
  //     other's address: an edge node is not a dial target and does not dial
  //     other edges;
  //   - an edge client DOES dial the infrastructure it learns (redundant
  //     reachability), so it ends up connected only to backbone;
  //   - two infrastructure nodes mesh (the lower id dials).
  tier::net::Node a = make_node(Role::transmitter);
  tier::net::Node b = make_node(Role::transmitter);
  tier::net::Node e1 = make_node(Role::client);
  tier::net::Node e2 = make_node(Role::client);

  // All initial links go to the hub A; everything else must be formed (or not
  // formed) by role-aware autodial off gossiped membership.
  b.connect("127.0.0.1", a.local_port());
  e1.connect("127.0.0.1", a.local_port());
  e2.connect("127.0.0.1", a.local_port());

  const auto converged = [&]() {
    return a.membership().size() == 4 && b.membership().size() == 4 &&
           e1.membership().size() == 4 && e2.membership().size() == 4 &&
           connected_to(a, b.peer_id()) &&
           connected_to(e1, a.peer_id()) && connected_to(e1, b.peer_id()) &&
           connected_to(e2, a.peer_id()) && connected_to(e2, b.peer_id());
  };

  for (int i = 0; i < 60000 && !converged(); ++i) {
    a.poll(2);
    b.poll(2);
    e1.poll(2);
    e2.poll(2);
  }

  // Everyone discovered everyone (gossip reaches the edge over its backbone
  // links). An edge client is a first-class participant.
  check(a.membership().size() == 4, "A sees all four");
  check(e1.membership().size() == 4, "edge E1 sees all four");
  check(e2.membership().size() == 4, "edge E2 sees all four");

  // Backbone meshes.
  check(connected_to(a, b.peer_id()), "backbone A connected to backbone B");

  // Each edge dialed the infrastructure it learned - redundant reachability to
  // both backbone nodes.
  check(connected_to(e1, a.peer_id()) && connected_to(e1, b.peer_id()),
        "edge E1 connected to both backbone nodes");
  check(connected_to(e2, a.peer_id()) && connected_to(e2, b.peer_id()),
        "edge E2 connected to both backbone nodes");

  // The core invariant: two edge clients never connect to each other, though
  // each holds the other's dialable address in membership.
  check(e1.membership().find(e2.peer_id()).has_value(),
        "E1 knows E2's record (so a dial was possible)");
  check(!connected_to(e1, e2.peer_id()), "edge E1 did not connect to edge E2");
  check(!connected_to(e2, e1.peer_id()), "edge E2 did not connect to edge E1");

  // And an edge node holds connections to backbone only - never to another edge.
  for (const auto& id : e1.connected_peers()) {
    check(id == a.peer_id() || id == b.peer_id(),
          "E1 is connected to backbone nodes only");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
