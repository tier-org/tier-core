#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

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

tier::net::Node make_node(std::uint16_t port) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(tier::core::Role::client),
                         "127.0.0.1", port);
}

}  // namespace

int main() {
  // A4 regression: bootstrap must keep retrying, so a node that started before
  // its seed (or whose seed was down at startup) reconnects on its own, with no
  // second bootstrap() call and no restart.

  // Grab a free loopback port by briefly binding it, then release it so the seed
  // is DOWN when the joiner first dials - the whole point of the test.
  std::uint16_t seed_port = 0;
  {
    tier::net::Node probe = make_node(0);
    seed_port = probe.local_port();
  }

  tier::net::Node joiner = make_node(0);
  const std::string seed_addr = "127.0.0.1:" + std::to_string(seed_port);
  joiner.bootstrap({seed_addr});

  // Pump the joiner alone for a bit: the seed is down, so it stays isolated.
  for (int i = 0; i < 50; ++i) {
    joiner.poll(10);
  }
  check(joiner.connected_peers().empty(),
        "joiner is isolated while the seed is down");

  // The seed appears late, on the address the joiner was told to dial.
  tier::net::Node seed = make_node(seed_port);

  // Without any further bootstrap() call, the joiner's retry must find it.
  const auto start = std::chrono::steady_clock::now();
  bool connected = false;
  while (std::chrono::steady_clock::now() - start < std::chrono::seconds(20)) {
    joiner.poll(10);
    seed.poll(10);
    if (joiner.membership().size() == 2 && seed.membership().size() == 2 &&
        !joiner.connected_peers().empty()) {
      connected = true;
      break;
    }
  }
  check(connected, "joiner reconnects to a late-arriving seed with no re-bootstrap");
  check(joiner.membership().find(seed.peer_id()).has_value(),
        "joiner learned the seed after retry");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
