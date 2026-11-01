#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>

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

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
