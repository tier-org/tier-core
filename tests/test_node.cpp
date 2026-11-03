#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>

#include "tier/core/control.hpp"
#include "tier/core/membership.hpp"
#include "tier/core/semver.hpp"
#include "tier/core/version.hpp"
#include "tier/core/version_range.hpp"
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

}  // namespace

int main() {
  using tier::core::Role;

  // A holds two roles at once (validator + keeper); the set must survive gossip.
  const tier::core::RoleSet a_roles =
      tier::core::role_bit(Role::validator) | tier::core::role_bit(Role::keeper);
  tier::net::Node a(tier::crypto::NodeIdentity::generate(), a_roles,
                    "127.0.0.1", 0);
  tier::net::Node b(tier::crypto::NodeIdentity::generate(),
                    tier::core::role_bit(Role::client), "127.0.0.1", 0);

  check(a.membership().size() == 1, "A starts knowing only itself");
  check(b.membership().size() == 1, "B starts knowing only itself");

  b.connect("127.0.0.1", a.local_port());

  for (int i = 0;
       i < 4000 && !(a.membership().size() == 2 && b.membership().size() == 2);
       ++i) {
    a.poll(5);
    b.poll(5);
  }

  check(a.membership().size() == 2, "A learned about B");
  check(b.membership().size() == 2, "B learned about A");

  const auto a_sees_b = a.membership().find(b.peer_id());
  check(a_sees_b.has_value(), "A has B in its membership");
  check(a_sees_b.has_value() && a_sees_b->roles == tier::core::role_bit(Role::client),
        "A sees B's role (client)");

  const auto b_sees_a = b.membership().find(a.peer_id());
  check(b_sees_a.has_value(), "B has A in its membership");
  check(b_sees_a.has_value() && tier::core::has_role(b_sees_a->roles, Role::validator),
        "B sees A as a validator");
  check(b_sees_a.has_value() && tier::core::has_role(b_sees_a->roles, Role::keeper),
        "B sees A as a keeper too (multi-role survived gossip)");

  // A node advertises its own software version, and it propagates via gossip.
  check(b_sees_a.has_value() && b_sees_a->version == tier::core::version(),
        "B sees A's version (propagated through gossip)");

  // Address confirmation: a single dual-stack peer that has observed us over
  // both IPv4 and IPv6 must yield BOTH addresses, not just the last reported.
  // Regression: observed_ once stored one address per peer and overwrote it, so
  // a dial-only node (highest id, only receives IPv6 autodials) collapsed to a
  // single family - in the field tier-04 advertised only IPv6 though its IPv4
  // was reachable.
  {
    using tier::core::PeerId;
    PeerId p1{};
    p1[0] = 1;
    PeerId p2{};
    p2[0] = 2;

    std::map<PeerId, std::set<std::string>> observed;
    observed[p1] = {"[2604:4500:9:7::2]:7777", "66.165.245.6:7777"};
    const auto both = tier::net::Node::confirmed_addresses(observed, 1);
    check(both.size() == 2, "one dual-stack peer confirms both families");
    check(std::find(both.begin(), both.end(), "66.165.245.6:7777") != both.end(),
          "IPv4 confirmed from a dual-stack peer");
    check(std::find(both.begin(), both.end(), "[2604:4500:9:7::2]:7777") !=
              both.end(),
          "IPv6 confirmed from a dual-stack peer");

    // Threshold still honored: an address seen by too few distinct peers is
    // withheld, and one seen by enough is kept.
    std::map<PeerId, std::set<std::string>> sparse;
    sparse[p1] = {"10.0.0.1:7777", "10.0.0.9:7777"};
    sparse[p2] = {"10.0.0.1:7777"};
    const auto quorum = tier::net::Node::confirmed_addresses(sparse, 2);
    check(quorum.size() == 1 && quorum.front() == "10.0.0.1:7777",
          "only an address backed by >= threshold distinct peers is confirmed");
  }

  // Version policy: a node refuses to admit a gossiped peer whose advertised
  // version is outside its network's window. Both nodes run this build's
  // version; D's range excludes it, so D never learns C, while C (unconstrained)
  // learns D. This is the membership-admission half of the version pin.
  {
    const auto current = tier::core::parse_semver(std::string(tier::core::version()));
    check(current.has_value(), "this build's version is valid semver");

    // A window that cannot contain the current version (far in the future).
    const auto exclude = tier::core::VersionRange{
        tier::core::parse_semver("9000.0.0"),
        tier::core::parse_semver("9000.1.0")};

    tier::net::Node c(tier::crypto::NodeIdentity::generate(),
                      tier::core::role_bit(Role::client), "127.0.0.1", 0);
    tier::net::Node d(tier::crypto::NodeIdentity::generate(),
                      tier::core::role_bit(Role::client), "127.0.0.1", 0, {},
                      "mainnet", exclude);

    d.connect("127.0.0.1", c.local_port());
    for (int i = 0; i < 2000 && c.membership().size() < 2; ++i) {
      c.poll(2);
      d.poll(2);
    }

    check(c.membership().size() == 2,
          "C (unconstrained) admits D despite D's own policy");
    check(d.membership().size() == 1,
          "D refuses C: C's version is outside D's version window");
    check(!d.membership().find(c.peer_id()).has_value(),
          "D never recorded C in membership");
  }

  // Owner-signed membership (A1 regression). A peer that completes the handshake
  // but is not the owner of a record cannot inject or alter that record: the
  // node verifies each gossiped record against the owner's key before merging.
  {
    using tier::core::Liveness;
    tier::net::Node victim(tier::crypto::NodeIdentity::generate(),
                           tier::core::role_bit(Role::client), "127.0.0.1", 0);
    const auto victim_id = victim.peer_id();

    // A bare endpoint with a different identity, standing in for a hostile peer.
    tier::net::Endpoint attacker(tier::crypto::NodeIdentity::generate(),
                                 "127.0.0.1", 0);
    tier::net::ConnId conn = 0;
    bool handshook = false;
    attacker.on_handshake(
        [&](tier::net::ConnId c, bool, const tier::net::PeerId&) {
          conn = c;
          handshook = true;
        });
    attacker.connect("127.0.0.1", victim.local_port());

    for (int i = 0; i < 4000 && !handshook; ++i) {
      attacker.poll(2);
      victim.poll(2);
    }
    check(handshook, "forgery: attacker completes the handshake");

    // Forge two records with no valid owner signature: a fabricated validator
    // peer, and a rewrite of the victim's own record (new roles, high
    // incarnation) - exactly the A1 scenario. Empty addresses so nothing is
    // dialed.
    tier::core::PeerInfo fake;
    fake.id.fill(0x77);
    fake.roles = tier::core::role_bit(Role::validator);
    fake.version = "1.0.0";
    fake.incarnation = 5;
    fake.liveness = Liveness::alive;

    tier::core::PeerInfo forged_self;
    forged_self.id = victim_id;
    forged_self.public_key.fill(0xAB);          // not the victim's key
    forged_self.signature.assign(64, 0xCD);     // garbage signature
    forged_self.roles = tier::core::role_bit(Role::validator) |
                        tier::core::role_bit(Role::keeper);
    forged_self.incarnation = 1000;             // tries to outrank the real one
    forged_self.version = std::string(tier::core::version());
    forged_self.liveness = Liveness::dead;      // tries to kill the victim

    const auto msg = tier::core::encode_membership_message({fake, forged_self});
    for (int i = 0; i < 400; ++i) {
      attacker.send(conn, msg);
      attacker.poll(2);
      victim.poll(2);
    }

    check(victim.membership().size() == 1,
          "forgery: victim admits no forged peer (still only itself)");
    check(!victim.membership().find(fake.id).has_value(),
          "forgery: fabricated peer rejected (id is not the hash of its key)");
    const auto self = victim.membership().find(victim_id);
    check(self.has_value() && self->roles == tier::core::role_bit(Role::client),
          "forgery: victim's own roles unchanged by the forged record");
    check(self.has_value() && self->liveness == Liveness::alive,
          "forgery: victim not marked dead by the forged record");
    check(self.has_value() && self->incarnation != 1000,
          "forgery: forged incarnation value did not become ours");
  }

  // Self-record authority across restart (A1 regression). A neighbor relays a
  // node's own OLD record - validly signed by the node's key, so verify_owner
  // accepts it - carrying a higher incarnation and a role the node no longer
  // runs (the post-restart rollback scenario). The node must not adopt it: its
  // configured role is authoritative and it refutes the stale record by raising
  // its incarnation above it.
  {
    using tier::core::Liveness;
    using tier::core::Role;

    // Build the node's identity from a seed we keep, so we can re-derive its
    // signer and forge a correctly-signed stale record for the same key.
    const auto seed = tier::crypto::NodeIdentity::generate().seed();
    const auto signer_identity = tier::crypto::NodeIdentity::from_seed(seed);

    tier::net::Node node(tier::crypto::NodeIdentity::from_seed(seed),
                         tier::core::role_bit(Role::client), "127.0.0.1", 0,
                         {}, "review");
    const auto node_id = node.peer_id();

    tier::net::Endpoint relay(tier::crypto::NodeIdentity::generate(),
                              "127.0.0.1", 0, "review");
    tier::net::ConnId conn = 0;
    bool handshook = false;
    relay.on_handshake([&](tier::net::ConnId c, bool, const tier::net::PeerId&) {
      conn = c;
      handshook = true;
    });
    relay.connect("127.0.0.1", node.local_port());
    for (int i = 0; i < 4000 && !handshook; ++i) {
      relay.poll(2);
      node.poll(2);
    }
    check(handshook, "restart: relay completes the handshake");

    // The stale, validly-signed self-record: an old validator+keeper role at a
    // high incarnation. Sign over the owner fields exactly as the node would.
    tier::core::PeerInfo stale;
    stale.id = node_id;
    stale.public_key = signer_identity.public_key();
    stale.roles = tier::core::role_bit(Role::validator) |
                  tier::core::role_bit(Role::keeper);
    stale.version = std::string(tier::core::version());
    stale.incarnation = 100;  // outranks the freshly restarted incarnation
    stale.liveness = Liveness::alive;
    stale.addresses = {};  // empty so nothing is dialed
    stale.signature = signer_identity.signer().sign(
        tier::core::membership_signing_payload("review", stale));

    const auto msg = tier::core::encode_membership_message({stale});
    for (int i = 0; i < 400; ++i) {
      relay.send(conn, msg);
      relay.poll(2);
      node.poll(2);
    }

    const auto self = node.membership().find(node_id);
    check(self.has_value() &&
              self->roles == tier::core::role_bit(Role::client),
          "restart: configured role wins over the stale signed record");
    check(self.has_value() && self->incarnation > 100,
          "restart: stale high incarnation is refuted, not adopted");
    check(self.has_value() && self->liveness == Liveness::alive,
          "restart: node stays alive");
  }

  // Restart incarnation recovery (regression for the mixed-deploy stale record).
  // A node re-enters the mesh with a wall-clock-seeded incarnation, not 1, so a
  // validly-signed record from a PREVIOUS run - necessarily a lower incarnation,
  // possibly in an old role the network still remembers - cannot override its
  // fresh record. This is what lets a node that was a client and is now backbone
  // reclaim its role after a staggered restart: the stale client record is
  // scoped out of gossip and could never be refuted the normal way, so losing on
  // incarnation is the mechanism that saves it.
  {
    using tier::core::Liveness;
    using tier::core::Role;
    const auto seed = tier::crypto::NodeIdentity::generate().seed();
    const auto signer = tier::crypto::NodeIdentity::from_seed(seed);

    tier::net::Node node(tier::crypto::NodeIdentity::from_seed(seed),
                         tier::core::role_bit(Role::transmitter), "127.0.0.1", 0,
                         {}, "review");
    const auto node_id = node.peer_id();
    const auto before = node.membership().find(node_id);
    const std::uint64_t fresh_inc = before ? before->incarnation : 0;
    check(fresh_inc > 1,
          "restart-inc: incarnation is seeded from the clock, not 1");

    tier::net::Endpoint relay(tier::crypto::NodeIdentity::generate(),
                              "127.0.0.1", 0, "review");
    tier::net::ConnId conn = 0;
    bool handshook = false;
    relay.on_handshake([&](tier::net::ConnId c, bool, const tier::net::PeerId&) {
      conn = c;
      handshook = true;
    });
    relay.connect("127.0.0.1", node.local_port());
    for (int i = 0; i < 4000 && !handshook; ++i) {
      relay.poll(2);
      node.poll(2);
    }
    check(handshook, "restart-inc: relay completes the handshake");

    // A correctly-signed record from an older run: a lower incarnation and the
    // old client role. verify_owner accepts it (same key), so only the
    // incarnation ordering keeps it from winning.
    tier::core::PeerInfo stale;
    stale.id = node_id;
    stale.public_key = signer.public_key();
    stale.roles = tier::core::role_bit(Role::client);
    stale.version = std::string(tier::core::version());
    stale.incarnation = fresh_inc - 1000;  // an earlier run, lower incarnation
    stale.liveness = Liveness::alive;
    stale.addresses = {};
    stale.signature = signer.signer().sign(
        tier::core::membership_signing_payload("review", stale));

    const auto msg = tier::core::encode_membership_message({stale});
    for (int i = 0; i < 400; ++i) {
      relay.send(conn, msg);
      relay.poll(2);
      node.poll(2);
    }

    const auto after = node.membership().find(node_id);
    check(after && tier::core::has_role(after->roles, Role::transmitter),
          "restart-inc: node keeps its backbone role against the older record");
    check(after && !tier::core::has_role(after->roles, Role::client),
          "restart-inc: stale client role from the old run does not take");
    check(after && after->incarnation >= fresh_inc,
          "restart-inc: incarnation not dragged down to the old run's value");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
