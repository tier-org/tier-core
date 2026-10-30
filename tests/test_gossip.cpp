#include <cstdio>

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
  return tier::net::Node(tier::crypto::NodeIdentity::generate(), role,
                         "127.0.0.1", 0);
}

}  // namespace

int main() {
  using tier::core::Role;

  // Star topology: B and C both dial the seed A. Neither B nor C ever connects
  // to the other, so each can only learn about the other through A's periodic
  // anti-entropy push. Convergence to all-know-all exercises that gossip.
  tier::net::Node a = make_node(Role::validator);
  tier::net::Node b = make_node(Role::client);
  tier::net::Node c = make_node(Role::client);

  b.connect("127.0.0.1", a.local_port());
  c.connect("127.0.0.1", a.local_port());

  for (int i = 0; i < 20000 &&
                  !(a.membership().size() == 3 && b.membership().size() == 3 &&
                    c.membership().size() == 3);
       ++i) {
    a.poll(2);
    b.poll(2);
    c.poll(2);
  }

  check(a.membership().size() == 3, "seed A sees all three");
  check(b.membership().size() == 3, "B sees all three");
  check(c.membership().size() == 3, "C sees all three");
  check(b.membership().find(c.peer_id()).has_value(),
        "B learned C transitively through the seed");
  check(c.membership().find(b.peer_id()).has_value(),
        "C learned B transitively through the seed");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
