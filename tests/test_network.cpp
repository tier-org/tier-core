#include <cstdio>
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

tier::net::Node make_node(const char* network) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(tier::core::Role::client),
                         "127.0.0.1", 0, {}, network);
}

}  // namespace

int main() {
  // Control: two nodes on the SAME network discover each other over a bootstrap
  // dial, exactly as an unconfigured (mainnet) pair would.
  {
    tier::net::Node a = make_node("mainnet");
    tier::net::Node b = make_node("mainnet");
    b.bootstrap({"127.0.0.1:" + std::to_string(a.local_port())});
    for (int i = 0;
         i < 4000 && !(a.membership().size() == 2 && b.membership().size() == 2);
         ++i) {
      a.poll(5);
      b.poll(5);
    }
    check(a.membership().size() == 2 && b.membership().size() == 2,
          "same-network peers discover each other");
  }

  // Isolation: a node on a different network must never be seen, even though b
  // dials a's address directly. The network name is folded into the ALPN token,
  // so the QUIC/TLS handshake fails closed and no membership is ever exchanged.
  {
    tier::net::Node a = make_node("testnet");
    tier::net::Node b = make_node("mainnet");
    b.bootstrap({"127.0.0.1:" + std::to_string(a.local_port())});
    bool crossed = false;
    for (int i = 0; i < 400; ++i) {
      a.poll(2);
      b.poll(2);
      if (a.membership().size() > 1 || b.membership().size() > 1) {
        crossed = true;
        break;
      }
    }
    check(!crossed, "cross-network nodes never enter each other's membership");
    check(a.connected_peers().empty() && b.connected_peers().empty(),
          "cross-network handshake never completes");
  }

  // A private network name is isolated from mainnet just the same.
  {
    tier::net::Node a = make_node("mainnet");
    tier::net::Node b = make_node("my-private-net");
    b.bootstrap({"127.0.0.1:" + std::to_string(a.local_port())});
    bool crossed = false;
    for (int i = 0; i < 400; ++i) {
      a.poll(2);
      b.poll(2);
      if (a.membership().size() > 1 || b.membership().size() > 1) {
        crossed = true;
        break;
      }
    }
    check(!crossed, "a private network is isolated from mainnet");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
