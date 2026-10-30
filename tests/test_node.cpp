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

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
