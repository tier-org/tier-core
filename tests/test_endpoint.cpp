#include <cstdio>
#include <span>
#include <vector>

#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"
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

  // Ping/echo over a QUIC stream: client sends "ping", server echoes it.
  const std::vector<tier::crypto::Byte> ping{0x70, 0x69, 0x6E, 0x67};  // "ping"
  std::vector<tier::crypto::Byte> echo_received;
  bool echo_done = false;

  server.set_auto_echo(true);
  client.set_auto_ping(ping);
  client.on_message([&](const tier::net::PeerId&,
                        std::span<const tier::crypto::Byte> payload) {
    echo_received.assign(payload.begin(), payload.end());
    echo_done = true;
  });

  client.connect("127.0.0.1", server.local_port());

  for (int i = 0; i < 4000 && !(server_done && client_done && echo_done); ++i) {
    client.poll(5);
    server.poll(5);
  }

  check(client.completed_handshakes() == 1, "client handshake completed");
  check(server.completed_handshakes() == 1, "server handshake completed");
  check(client_saw_peer == server_identity.public_key(),
        "client authenticated the server's Ed25519 identity");
  check(server_saw_peer == client_identity.public_key(),
        "server authenticated the client's Ed25519 identity");
  check(echo_done, "client received an echo frame");
  check(echo_received == ping, "echo payload matches the ping");
  check(client.last_negotiated_group() == "X25519MLKEM768",
        "key exchange negotiated the hybrid ML-KEM group");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
