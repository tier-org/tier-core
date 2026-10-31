#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/core/seeds.hpp"
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

bool contains(const std::vector<std::string>& v, const std::string& s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

tier::net::Node make_node(const char* ip, std::uint16_t port) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(tier::core::Role::client), ip,
                         port);
}

}  // namespace

int main() {
  // The baked seed list: two dialable "ip:port" per seed, IPv6 bracketed.
  const auto seeds = tier::core::default_seed_addresses();
  check(seeds.size() == std::size(tier::core::kSeedNodes) * 2,
        "two addresses per seed node");
  check(contains(seeds, "[2a0b:8c40:1::143]:7777"), "tier-01 IPv6 bracketed");
  check(contains(seeds, "66.220.12.143:7777"), "tier-01 IPv4 with port");
  check(contains(seeds, "66.165.245.6:7777"), "tier-04 IPv4 with port");
  check(contains(seeds, "[2604:4500:9:7::2]:7777"), "tier-04 IPv6 bracketed");

  // Bootstrap joins the network: B dials A purely from a seed address, with no
  // prior knowledge of A, and the two exchange membership.
  {
    tier::net::Node a = make_node("127.0.0.1", 0);
    tier::net::Node b = make_node("127.0.0.1", 0);
    b.bootstrap({"127.0.0.1:" + std::to_string(a.local_port())});

    for (int i = 0;
         i < 4000 && !(a.membership().size() == 2 && b.membership().size() == 2);
         ++i) {
      a.poll(5);
      b.poll(5);
    }
    check(a.membership().size() == 2, "A learned B via B's bootstrap dial");
    check(b.membership().size() == 2, "B learned A by bootstrapping to it");
  }

  // A node that is itself a seed must not dial its own advertised address: with
  // a concrete bind the address matches self_address_ and is skipped outright.
  {
    tier::net::Node c = make_node("127.0.0.1", 0);
    c.bootstrap({"127.0.0.1:" + std::to_string(c.local_port())});
    for (int i = 0; i < 200; ++i) {
      c.poll(5);
    }
    check(c.membership().size() == 1, "self seed address is not dialed");
    check(c.connected_peers().empty(), "no self connection from bootstrap");
  }

  // The last line of defense: even a self-dial that slips past the address
  // filter (e.g. a wildcard-bound seed dialing its own public IP) never becomes
  // a neighbor or a membership peer.
  {
    tier::net::Node d = make_node("127.0.0.1", 0);
    const tier::core::PeerId self = d.peer_id();
    d.connect("127.0.0.1", d.local_port());  // dial self, bypassing bootstrap
    bool saw_self = false;
    for (int i = 0; i < 300; ++i) {
      d.poll(5);
      const auto peers = d.connected_peers();
      if (std::find(peers.begin(), peers.end(), self) != peers.end()) {
        saw_self = true;
        break;
      }
    }
    check(!saw_self, "a self-connection is never routed as a neighbor");
    check(d.membership().size() == 1, "a self-dial adds no membership peer");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
