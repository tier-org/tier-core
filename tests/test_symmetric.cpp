// Two endpoints dial each other at the same time over one shared socket each.
// Because a node both listens and dials from its single :port socket, each side
// holds an outbound connection to the other's address while the other's Initial
// arrives at that same address. Routing inbound packets by peer address (the
// old behavior) fed each Initial into the local outbound client connection,
// which never accepts it as a server, so neither handshake ever completed.
// Routing by Connection ID fixes it. This reproduces the field deadlock where a
// simultaneous cold start left every node at known=1 connected=0.
#include <cstdio>

#include "tier/crypto/identity.hpp"
#include "tier/net/endpoint.hpp"

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
  const auto id_a = tier::crypto::NodeIdentity::generate();
  const auto id_b = tier::crypto::NodeIdentity::generate();

  tier::net::Endpoint a(id_a, "127.0.0.1", 0);
  tier::net::Endpoint b(id_b, "127.0.0.1", 0);

  bool a_done = false;
  bool b_done = false;
  a.on_handshake([&](tier::net::ConnId, bool, const tier::net::PeerId&) {
    a_done = true;
  });
  b.on_handshake([&](tier::net::ConnId, bool, const tier::net::PeerId&) {
    b_done = true;
  });

  // Both dial before either polls: neither is "the server".
  a.connect("127.0.0.1", b.local_port());
  b.connect("127.0.0.1", a.local_port());

  for (int i = 0; i < 4000 && !(a_done && b_done); ++i) {
    a.poll(5);
    b.poll(5);
  }

  check(a_done, "A completed a handshake under a symmetric dial");
  check(b_done, "B completed a handshake under a symmetric dial");

  // Both must see each other in their live connection set.
  check(!a.connections().empty(), "A holds a live connection");
  check(!b.connections().empty(), "B holds a live connection");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
