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
  const auto server_identity = tier::crypto::NodeIdentity::generate();
  const auto client_identity = tier::crypto::NodeIdentity::generate();

  tier::net::Endpoint server(server_identity, "127.0.0.1", 0);
  tier::net::Endpoint client(client_identity, "127.0.0.1", 0);

  tier::net::PeerId server_saw_peer{};
  tier::net::PeerId client_saw_peer{};
  bool server_done = false;
  bool client_done = false;

  server.on_handshake([&](const tier::net::PeerId& peer) {
    server_saw_peer = peer;
    server_done = true;
  });
  client.on_handshake([&](const tier::net::PeerId& peer) {
    client_saw_peer = peer;
    client_done = true;
  });

  client.connect("127.0.0.1", server.local_port());

  for (int i = 0; i < 2000 && !(server_done && client_done); ++i) {
    client.poll(5);
    server.poll(5);
  }

  check(client.completed_handshakes() == 1, "client handshake completed");
  check(server.completed_handshakes() == 1, "server handshake completed");
  check(client_saw_peer == server_identity.public_key(),
        "client authenticated the server's Ed25519 identity");
  check(server_saw_peer == client_identity.public_key(),
        "server authenticated the client's Ed25519 identity");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
