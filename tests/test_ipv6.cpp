#include <cstdio>

#include "tier/crypto/identity.hpp"
#include "tier/net/endpoint.hpp"

// Native IPv6: two endpoints bound to ::1 complete a handshake. Proves the
// dual-stack socket speaks IPv6 (the other tests exercise IPv4 via ::ffff:).
int main() {
  const auto server_id = tier::crypto::NodeIdentity::generate();
  const auto client_id = tier::crypto::NodeIdentity::generate();

  tier::net::Endpoint server(server_id, "::1", 0);
  tier::net::Endpoint client(client_id, "::1", 0);

  bool server_done = false;
  bool client_done = false;
  server.on_handshake(
      [&](tier::net::ConnId, bool, const tier::net::PeerId&) { server_done = true; });
  client.on_handshake(
      [&](tier::net::ConnId, bool, const tier::net::PeerId&) { client_done = true; });

  client.connect("::1", server.local_port());

  for (int i = 0; i < 4000 && !(server_done && client_done); ++i) {
    client.poll(5);
    server.poll(5);
  }

  if (server_done && client_done) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "FAIL: IPv6 handshake did not complete\n");
  return 1;
}
