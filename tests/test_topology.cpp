#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "tier/core/control.hpp"
#include "tier/core/membership.hpp"
#include "tier/core/version.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/net/endpoint.hpp"
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

// A raw endpoint standing in for an owner that publishes its own record and
// answers SWIM pings (so it is not reaped mid-test). Its records carry empty
// addresses, so no node ever dials it directly: it is reachable only over the
// connection it opened, which keeps the relay the sole path to downstream peers.
struct Publisher {
  tier::crypto::NodeIdentity identity;
  tier::net::Endpoint endpoint;
  std::string network;
  tier::net::ConnId conn = 0;
  bool handshook = false;

  Publisher(std::array<std::uint8_t, 32> seed, std::string net)
      : identity(tier::crypto::NodeIdentity::from_seed(seed)),
        endpoint(tier::crypto::NodeIdentity::from_seed(seed), "127.0.0.1", 0,
                 net),
        network(std::move(net)) {
    endpoint.on_handshake(
        [this](tier::net::ConnId c, bool, const tier::core::PeerId&) {
          conn = c;
          handshook = true;
        });
    // Answer liveness pings so the detector keeps us alive for the whole test.
    endpoint.on_message([this](tier::net::ConnId c, const tier::core::PeerId&,
                               std::span<const std::uint8_t> p) {
      if (tier::core::peek_control_type(p) == tier::core::ControlType::ping) {
        if (const auto ping = tier::core::decode_ping(p)) {
          endpoint.send(c, tier::core::encode_ack(ping->seq));
        }
      }
    });
  }

  tier::core::PeerId id() const { return tier::crypto::sha256(identity.public_key()); }

  // Our own signed record at `roles`/`incarnation`, no addresses.
  tier::core::PeerInfo record(tier::core::RoleSet roles,
                              std::uint64_t incarnation) const {
    tier::core::PeerInfo p;
    p.id = id();
    p.public_key = identity.public_key();
    p.roles = roles;
    p.version = std::string(tier::core::version());
    p.incarnation = incarnation;
    p.liveness = tier::core::Liveness::alive;
    p.signature = identity.signer().sign(
        tier::core::membership_signing_payload(network, p));
    return p;
  }

  void publish(const tier::core::PeerInfo& p) {
    endpoint.send(conn, tier::core::encode_membership_message({p}));
  }
};

// What a node currently thinks a peer's roles are, if it knows the peer.
bool sees_infrastructure(const tier::net::Node& n, const tier::core::PeerId& id) {
  const auto rec = n.membership().find(id);
  return rec.has_value() && tier::core::is_infrastructure(rec->roles);
}

// A6 (docs/topology.md): an owner that drops from an infrastructure role to
// plain client must have that demotion reach the whole network, not just the
// neighbor it is connected to. The scoping filter forwards only
// infrastructure+self records, so without the demotion-propagation window the
// downstream node keeps the stale transmitter record and still treats the owner
// as backbone.
void role_demotion_propagation() {
  using tier::core::Role;
  const tier::core::RoleSet kTransmitter = tier::core::role_bit(Role::transmitter);
  const tier::core::RoleSet kClient = tier::core::role_bit(Role::client);

  // Case 1: immediate rumor path. publisher -> relay -> downstream, with no
  // direct publisher<->downstream link (publisher advertises no address).
  {
    tier::net::Node relay(tier::crypto::NodeIdentity::generate(), kTransmitter,
                          "127.0.0.1", 0, {}, "review");
    tier::net::Node downstream(tier::crypto::NodeIdentity::generate(),
                               kTransmitter, "127.0.0.1", 0, {}, "review");
    Publisher pub(tier::crypto::NodeIdentity::generate().seed(), "review");

    downstream.connect("127.0.0.1", relay.local_port());
    pub.endpoint.connect("127.0.0.1", relay.local_port());

    const auto pump = [&] {
      relay.poll(2);
      downstream.poll(2);
      pub.endpoint.poll(2);
    };

    // Owner announces an infrastructure role; it propagates relay -> downstream
    // normally (a transmitter record is gossiped by role).
    for (int i = 0; i < 6000 && !sees_infrastructure(downstream, pub.id());
         ++i) {
      pub.publish(pub.record(kTransmitter, 100));
      pump();
    }
    check(sees_infrastructure(downstream, pub.id()),
          "A6: downstream learns the owner as infrastructure via the relay");

    // Owner signs a newer record demoting itself to client. Downstream must stop
    // treating it as infrastructure, reached only through the relay.
    const auto demoted = pub.record(kClient, 101);
    bool converged = false;
    for (int i = 0; i < 6000 && !converged; ++i) {
      pub.publish(demoted);
      pump();
      const auto rec = downstream.membership().find(pub.id());
      converged = rec.has_value() && rec->incarnation == 101 &&
                  !tier::core::is_infrastructure(rec->roles);
    }
    const auto rec = downstream.membership().find(pub.id());
    check(rec.has_value() && rec->incarnation == 101,
          "A6: downstream receives the newer demoted record");
    check(rec.has_value() && !tier::core::is_infrastructure(rec->roles),
          "A6: downstream no longer treats the demoted owner as infrastructure");
    check(rec.has_value() && rec->roles == kClient,
          "A6: downstream sees the owner's client role");
  }

  // Case 2: anti-entropy path for a node that was not connected when the
  // demotion rumor was sent. The relay applies the demotion first; a downstream
  // that joins afterwards must still learn it from the relay's periodic full
  // sync (the demotion-propagation window keeps it in gossip_records).
  {
    tier::net::Node relay(tier::crypto::NodeIdentity::generate(), kTransmitter,
                          "127.0.0.1", 0, {}, "review");
    Publisher pub(tier::crypto::NodeIdentity::generate().seed(), "review");
    pub.endpoint.connect("127.0.0.1", relay.local_port());

    const auto pump_relay = [&] {
      relay.poll(2);
      pub.endpoint.poll(2);
    };

    for (int i = 0; i < 6000 && !sees_infrastructure(relay, pub.id()); ++i) {
      pub.publish(pub.record(kTransmitter, 100));
      pump_relay();
    }
    check(sees_infrastructure(relay, pub.id()),
          "A6: relay learns the owner as infrastructure");

    const auto demoted = pub.record(kClient, 101);
    bool relay_demoted = false;
    for (int i = 0; i < 6000 && !relay_demoted; ++i) {
      pub.publish(demoted);
      pump_relay();
      const auto rec = relay.membership().find(pub.id());
      relay_demoted = rec.has_value() && rec->incarnation == 101 &&
                      !tier::core::is_infrastructure(rec->roles);
    }
    check(relay_demoted, "A6: relay applied the demotion");

    // Only now does the downstream join. It never saw the rumor; it must learn
    // the client role from the relay's gossip, within the demotion window.
    tier::net::Node downstream(tier::crypto::NodeIdentity::generate(),
                               kTransmitter, "127.0.0.1", 0, {}, "review");
    downstream.connect("127.0.0.1", relay.local_port());

    bool learned = false;
    for (int i = 0; i < 6000 && !learned; ++i) {
      pub.publish(demoted);
      relay.poll(2);
      downstream.poll(2);
      pub.endpoint.poll(2);
      const auto rec = downstream.membership().find(pub.id());
      learned = rec.has_value() && rec->incarnation == 101;
    }
    const auto rec = downstream.membership().find(pub.id());
    check(rec.has_value() && rec->incarnation == 101,
          "A6: late-joining downstream learns the demoted record via anti-entropy");
    check(rec.has_value() && !tier::core::is_infrastructure(rec->roles),
          "A6: late joiner does not treat the demoted owner as infrastructure");
  }
}

// A6 remainder (docs/audit-2026-11-01.md, 0.5.0 re-review): a node that learned
// the owner's fresh client record first, then receives a STALE infrastructure
// announcement for the same owner from a neighbor, must push its newer record
// back so the neighbor converges - instead of silently dropping the stale
// record and leaving the neighbor to keep treating the demoted owner as
// backbone. This covers the case where the node holding the fresh record never
// witnessed the infra->client transition locally (no demotion window was set),
// so only the push-back on a rejected stale merge carries the revocation.
void role_demotion_pushback() {
  using tier::core::Role;
  const tier::core::RoleSet kTransmitter = tier::core::role_bit(Role::transmitter);
  const tier::core::RoleSet kClient = tier::core::role_bit(Role::client);

  tier::net::Node relay(tier::crypto::NodeIdentity::generate(), kTransmitter,
                        "127.0.0.1", 0, {}, "review");
  tier::net::Node downstream(tier::crypto::NodeIdentity::generate(), kTransmitter,
                             "127.0.0.1", 0, {}, "review");
  // One owner identity published through two endpoints, so the stale infra
  // record and the fresh client record reach downstream and relay over separate
  // connections - the fresh client record is never sent to downstream directly,
  // so the only way downstream can learn it is relay's push-back.
  const std::array<std::uint8_t, 32> owner_seed =
      tier::crypto::NodeIdentity::generate().seed();
  Publisher pub_d(owner_seed, "review");  // to downstream: infra@100
  Publisher pub_r(owner_seed, "review");  // to relay: client@101

  // Phase 1: the owner tells `downstream` it is a transmitter at incarnation 100.
  pub_d.endpoint.connect("127.0.0.1", downstream.local_port());
  for (int i = 0; i < 6000 && !sees_infrastructure(downstream, pub_d.id()); ++i) {
    pub_d.publish(pub_d.record(kTransmitter, 100));
    downstream.poll(2);
    pub_d.endpoint.poll(2);
  }
  check(sees_infrastructure(downstream, pub_d.id()),
        "A6 pushback: downstream holds the stale infrastructure record");

  // Phase 2: the owner announces its demotion to client@101 only to `relay`.
  // `relay` learns the fresh client record directly and, never having seen an
  // infra->client transition for it, sets no demotion window and does not gossip
  // it by role.
  pub_r.endpoint.connect("127.0.0.1", relay.local_port());
  bool relay_has_client = false;
  for (int i = 0; i < 6000 && !relay_has_client; ++i) {
    pub_r.publish(pub_r.record(kClient, 101));
    relay.poll(2);
    downstream.poll(2);
    pub_d.endpoint.poll(2);
    pub_r.endpoint.poll(2);
    const auto rec = relay.membership().find(pub_r.id());
    relay_has_client = rec.has_value() && rec->incarnation == 101 &&
                       !tier::core::is_infrastructure(rec->roles);
  }
  check(relay_has_client, "A6 pushback: relay holds the fresh client record");
  // downstream must still hold only the stale infra record at this point.
  check(sees_infrastructure(downstream, pub_d.id()),
        "A6 pushback: downstream has not learned the client record directly");

  // Phase 3: connect relay and downstream. downstream gossips its stale infra
  // record to relay; relay rejects it as older but must push its client@101 back
  // so downstream converges. The owner never re-publishes to downstream here, so
  // convergence can only come from relay's push-back.
  downstream.connect("127.0.0.1", relay.local_port());
  bool converged = false;
  for (int i = 0; i < 6000 && !converged; ++i) {
    relay.poll(2);
    downstream.poll(2);
    pub_d.endpoint.poll(2);
    pub_r.endpoint.poll(2);
    const auto rec = downstream.membership().find(pub_d.id());
    converged = rec.has_value() && rec->incarnation == 101 &&
                !tier::core::is_infrastructure(rec->roles);
  }
  const auto rec = downstream.membership().find(pub_d.id());
  check(rec.has_value() && rec->incarnation == 101,
        "A6 pushback: downstream converges to the client record via push-back");
  check(rec.has_value() && !tier::core::is_infrastructure(rec->roles),
        "A6 pushback: downstream drops the stale infrastructure status");
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
  role_demotion_propagation();
  role_demotion_pushback();

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
