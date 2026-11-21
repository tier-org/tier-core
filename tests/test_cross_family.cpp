// End-to-end regression for cross-address-family messaging: a v6-only edge
// (bound to ::1) sends to a v4-only edge (bound to 127.0.0.1). The two can never
// connect directly or hole-punch (disjoint families), so delivery must go over a
// relay - and the relay has to be a communicator the v4-only target can also
// reach. The responsible set here is {commBad, commGood}: commBad is v6-only, so
// the v4-only target never enrolled with it; commGood is dual-stack, reachable by
// both. commBad is deliberately ground to sort FIRST in the target's responsible
// order, so the old "relay through the first connected responsible" would hand the
// frame to commBad, which holds no connection to the target, and black-hole it.
// The fix (choose_relay_communicator) must route through commGood instead.
//
// Loopback reproduces production faithfully: a dual-stack node ("::" bind) learns
// and advertises both its 127.0.0.1 and its [::1] address via observed_addr (see
// test_dualstack), so is_ipv6-based family classification matches a real mesh.
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/net/node.hpp"
#include "tier/net/rendezvous.hpp"

namespace {

using tier::crypto::Byte;
using tier::msg::Suite;
using Clock = std::chrono::steady_clock;

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

tier::crypto::ByteSpan sp(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

tier::core::PeerId id_of(const tier::crypto::NodeIdentity& id) {
  const auto& pub = id.public_key();
  return tier::crypto::sha256(tier::crypto::ByteSpan(pub.data(), pub.size()));
}

tier::net::Node make_node(tier::core::Role role, const std::string& bind,
                          tier::crypto::NodeIdentity id) {
  return tier::net::Node(std::move(id), tier::core::role_bit(role), bind, 0);
}

void pump(const std::vector<tier::net::Node*>& nodes, int n) {
  for (int i = 0; i < n; ++i) {
    for (auto* node : nodes) node->poll(2);
  }
}

bool pump_until(const std::vector<tier::net::Node*>& nodes,
                const std::function<bool()>& cond, int max_ms) {
  const auto deadline = Clock::now() + std::chrono::milliseconds(max_ms);
  while (Clock::now() < deadline) {
    pump(nodes, 1);
    if (cond()) return true;
  }
  return cond();
}

}  // namespace

int main() {
  using tier::core::Role;

  // Target identity first, then grind the two communicators so that, for the
  // target, commBad outranks commGood (commBad is responsible-first). This makes
  // the pre-fix code deterministically pick the unreachable relay.
  const auto target_id = tier::crypto::NodeIdentity::generate();
  const auto tid = id_of(target_id);

  auto good_id = tier::crypto::NodeIdentity::generate();
  auto bad_id = tier::crypto::NodeIdentity::generate();
  for (int tries = 0; tries < 100000; ++tries) {
    const auto top = tier::net::responsible_communicators(
        tid, {id_of(good_id), id_of(bad_id)}, 1);
    if (!top.empty() && top.front() == id_of(bad_id)) break;
    bad_id = tier::crypto::NodeIdentity::generate();
  }
  check(tier::net::responsible_communicators(
            tid, {id_of(good_id), id_of(bad_id)}, 1)
                .front() == id_of(bad_id),
        "ground commBad to be the target's first responsible communicator");

  // commGood: dual-stack (reachable by both families). commBad: v6-only.
  tier::net::Node comm_good =
      make_node(Role::communicator, "::", std::move(good_id));
  tier::net::Node comm_bad =
      make_node(Role::communicator, "::1", std::move(bad_id));
  // target: v4-only edge. sender: v6-only edge.
  tier::net::Node target =
      make_node(Role::client, "127.0.0.1", std::move(target_id));
  tier::net::Node sender = make_node(Role::client, "::1",
                                     tier::crypto::NodeIdentity::generate());

  std::vector<tier::net::Node*> all{&comm_good, &comm_bad, &target, &sender};

  // Wiring (outbound dials only, as edges behind NAT would do):
  //  - the two communicators peer with each other over IPv6 and gossip;
  //  - target reaches only the dual-stack communicator (it is v4-only);
  //  - sender reaches both communicators over IPv6.
  comm_bad.connect("::1", comm_good.local_port());
  target.connect("127.0.0.1", comm_good.local_port());
  sender.connect("::1", comm_good.local_port());
  sender.connect("::1", comm_bad.local_port());

  // Let membership converge and the target register its presence. The target
  // must end up enrolled with commGood (reachable) and NOT commBad (v6-only).
  check(pump_until(all,
                   [&] {
                     return sender.has_encryption_keys(comm_good.peer_id()) &&
                            sender.has_encryption_keys(comm_bad.peer_id()) &&
                            target.has_encryption_keys(comm_good.peer_id());
                   },
                   20000),
        "sender reached both communicators; target reached the dual-stack one");
  pump(all, 400);  // settle presence registration + gossip of the comm set

  // Sanity: the target cannot reach the v6-only communicator.
  {
    bool target_on_bad = false;
    for (const auto& p : target.connected_peers()) {
      if (p == comm_bad.peer_id()) target_on_bad = true;
    }
    check(!target_on_bad, "v4-only target holds no connection to the v6-only comm");
  }

  // Send from the v6-only sender to the v4-only target.
  const auto pt = bytes("cross-family hello, relayed through the dual-stack comm");
  check(sender.send_message(target.peer_id(), Suite::hybrid, sp(pt)) ==
            tier::net::Node::SendResult::queued,
        "cross-family send is queued");

  bool got = false;
  const bool arrived = pump_until(
      all,
      [&] {
        for (const auto& m : target.take_inbox()) {
          if (m.plaintext == pt) {
            got = true;
            check(m.sender == sender.peer_id(),
                  "relayed sender authenticated end-to-end");
          }
        }
        return got;
      },
      30000);
  check(arrived,
        "message crossed from v6-only sender to v4-only target over the relay");

  // It was a relay, never a direct cross-family connection.
  bool direct = false;
  for (const auto& p : sender.connected_peers()) {
    if (p == target.peer_id()) direct = true;
  }
  check(!direct, "no direct v6<->v4 connection formed (relay, not punch)");

  // --- part 2: the Offline-badge clobber (user presence) ---
  // A v4-only host enrols its user with the responsible communicators it can
  // reach: commGood (dual-stack), never commBad (v6-only). A v6 watcher queries
  // both; commBad answers "empty" every round. Pre-fix, that empty clobbered the
  // online answer from commGood, so the user read as stuck/flapping Offline. The
  // fix keeps the user Online as long as any replica reports it online. Reuses
  // the two communicators already meshed above.
  using Presence = tier::net::Node::Presence;
  tier::net::Node host =
      make_node(Role::client, "127.0.0.1", tier::crypto::NodeIdentity::generate());
  const auto uid = host.add_user(tier::crypto::NodeIdentity::generate());
  host.set_user_presence(uid, true);
  tier::net::Node watcher =
      make_node(Role::client, "::1", tier::crypto::NodeIdentity::generate());
  host.connect("127.0.0.1", comm_good.local_port());  // v4 -> dual-stack only
  watcher.connect("::1", comm_good.local_port());
  watcher.connect("::1", comm_bad.local_port());
  std::vector<tier::net::Node*> pmesh{&comm_good, &comm_bad, &host, &watcher};

  check(pump_until(pmesh,
                   [&] { return watcher.query_user_presence(uid) ==
                                Presence::online; },
                   20000),
        "watcher resolves the cross-family user online");

  // And it must STAY online across several refresh rounds (> 2*kPresenceRefresh),
  // not flap to offline when commBad's empty answer lands.
  bool ever_offline = false;
  const auto hold = Clock::now() + std::chrono::milliseconds(6000);
  while (Clock::now() < hold) {
    pump(pmesh, 1);
    if (watcher.query_user_presence(uid) == Presence::offline) {
      ever_offline = true;
    }
  }
  check(!ever_offline,
        "user stays Online despite the v6-only replica answering empty");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
