#include <cstdio>

#include "tier/crypto/identity.hpp"
#include "tier/net/node.hpp"

// A node bound to the IPv6 wildcard "::" runs on a dual-stack socket, so it is
// reachable over both IPv4 (v4-mapped) and native IPv6 at the same time. Two
// clients dial it, one per family; the node must accept both and, learning its
// reachable address from each via observed_addr, end up advertising both its
// IPv4 and its IPv6 address.

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
                         tier::core::role_bit(role), "::", 0);
}

bool advertises_prefix(const tier::net::Node& n, const char* prefix) {
  const auto self = n.membership().find(n.peer_id());
  if (!self) {
    return false;
  }
  for (const auto& addr : self->addresses) {
    if (addr.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  using tier::core::Role;

  tier::net::Node server = make_node(Role::validator);
  tier::net::Node c4 = make_node(Role::client);
  tier::net::Node c6 = make_node(Role::client);
  const std::uint16_t port = server.local_port();

  c4.connect("127.0.0.1", port);  // IPv4, arrives v4-mapped on the dual socket
  c6.connect("::1", port);        // native IPv6

  bool ready = false;
  for (int i = 0; i < 40000 && !ready; ++i) {
    server.poll(2);
    c4.poll(2);
    c6.poll(2);
    ready = server.connected_peers().size() >= 2 &&
            advertises_prefix(server, "127.0.0.1:") &&
            advertises_prefix(server, "[::1]:");
  }

  check(server.connected_peers().size() >= 2,
        "server accepted connections over both families");
  check(advertises_prefix(server, "127.0.0.1:"),
        "server advertises its IPv4 address");
  check(advertises_prefix(server, "[::1]:"),
        "server advertises its IPv6 address");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
