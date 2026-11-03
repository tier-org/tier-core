#include <algorithm>
#include <array>
#include <cstdio>
#include <set>
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

// Build n distinct, sorted backbone ids.
std::vector<tier::core::PeerId> make_ids(std::size_t n) {
  std::vector<tier::core::PeerId> ids;
  for (std::size_t i = 0; i < n; ++i) {
    tier::core::PeerId id{};
    id[0] = static_cast<std::uint8_t>(i);
    id[1] = static_cast<std::uint8_t>((i * 37) & 0xFF);
    ids.push_back(id);
  }
  std::sort(ids.begin(), ids.end());
  return ids;
}

// Bounded-degree ring selection properties (Phase 2), tested on the pure helper.
void ring_properties() {
  constexpr std::size_t kBackbone = 8;  // must match node.cpp
  constexpr std::size_t kClient = 3;

  for (const std::size_t n : {2u, 4u, 9u, 20u, 50u}) {
    const auto ids = make_ids(n);
    const std::set<tier::core::PeerId> id_set(ids.begin(), ids.end());

    // Per-node backbone targets.
    std::vector<std::vector<tier::core::PeerId>> targ(n);
    for (std::size_t i = 0; i < n; ++i) {
      targ[i] = tier::net::Node::ring_dial_targets(ids, ids[i], true, kBackbone,
                                                   kClient);
    }

    // Degree bound, and full mesh only when the backbone is small enough.
    for (std::size_t i = 0; i < n; ++i) {
      check(targ[i].size() <= kBackbone, "backbone degree within bound");
      if (n - 1 <= kBackbone) {
        check(targ[i].size() == n - 1, "small backbone is a full mesh");
      }
      for (const auto& t : targ[i]) {
        check(id_set.count(t) == 1 && !(t == ids[i]),
              "target is another backbone id");
      }
    }

    // Symmetry: j is a target of i iff i is a target of j (so the lower-id
    // tie-break yields exactly one connection per edge).
    const auto has = [](const std::vector<tier::core::PeerId>& v,
                        const tier::core::PeerId& x) {
      return std::find(v.begin(), v.end(), x) != v.end();
    };
    for (std::size_t i = 0; i < n; ++i) {
      for (std::size_t j = 0; j < n; ++j) {
        check(has(targ[i], ids[j]) == has(targ[j], ids[i]),
              "backbone target relation is symmetric");
      }
    }

    // Connectivity: the undirected target graph is connected (BFS from 0).
    std::vector<bool> seen(n, false);
    std::vector<std::size_t> stack{0};
    seen[0] = true;
    std::size_t reached = 1;
    const auto index_of = [&](const tier::core::PeerId& x) {
      return static_cast<std::size_t>(
          std::lower_bound(ids.begin(), ids.end(), x) - ids.begin());
    };
    while (!stack.empty()) {
      const std::size_t u = stack.back();
      stack.pop_back();
      for (const auto& t : targ[u]) {
        const std::size_t v = index_of(t);
        if (!seen[v]) {
          seen[v] = true;
          ++reached;
          stack.push_back(v);
        }
      }
    }
    check(reached == n, "backbone ring graph is connected");
  }

  // Edge fanout: an edge node (not in the list) targets min(kClient, n) backbone
  // entry points, all from the backbone list.
  {
    const auto ids = make_ids(20);
    tier::core::PeerId self{};
    self[0] = 100;  // not among ids (which use i in 0..19)
    const auto t = tier::net::Node::ring_dial_targets(ids, self, false, kBackbone,
                                                     kClient);
    check(t.size() == kClient, "edge targets kClientFanout backbone nodes");
    const std::set<tier::core::PeerId> id_set(ids.begin(), ids.end());
    for (const auto& x : t) {
      check(id_set.count(x) == 1, "edge target is a backbone id");
    }
  }
}

int main() {
  using tier::core::Role;

  ring_properties();

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

  // Membership scoping (Phase 3a): backbone records propagate network-wide;
  // an edge client's record stays local to the backbone it attaches to and is
  // never re-gossiped. So backbone sees everyone (both backbone + both attached
  // edges = 4), while an edge sees only backbone plus itself (3), never the
  // other edge.
  const auto converged = [&]() {
    return a.membership().size() == 4 && b.membership().size() == 4 &&
           e1.membership().size() == 3 && e2.membership().size() == 3 &&
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

  // Backbone holds the whole picture: both backbone nodes and both attached
  // edge clients.
  check(a.membership().size() == 4, "backbone A sees all four (both edges attached)");
  check(b.membership().size() == 4, "backbone B sees all four");

  // An edge sees only backbone + itself; it never learns the other edge, since
  // backbone does not re-gossip edge records.
  check(e1.membership().size() == 3, "edge E1 sees backbone + itself only");
  check(!e1.membership().find(e2.peer_id()).has_value(),
        "edge E1 never learns edge E2 (scoped out of gossip)");
  check(!e2.membership().find(e1.peer_id()).has_value(),
        "edge E2 never learns edge E1");

  // Backbone meshes.
  check(connected_to(a, b.peer_id()), "backbone A connected to backbone B");

  // Each edge dialed the infrastructure it learned - redundant reachability to
  // both backbone nodes - and to nothing else.
  check(connected_to(e1, a.peer_id()) && connected_to(e1, b.peer_id()),
        "edge E1 connected to both backbone nodes");
  check(connected_to(e2, a.peer_id()) && connected_to(e2, b.peer_id()),
        "edge E2 connected to both backbone nodes");
  check(!connected_to(e1, e2.peer_id()), "edge E1 did not connect to edge E2");
  check(!connected_to(e2, e1.peer_id()), "edge E2 did not connect to edge E1");
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
