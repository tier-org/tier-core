#include <cstdio>
#include <vector>

#include "tier/core/control.hpp"
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

// Bind the wildcard so each node starts out advertising "0.0.0.0:port", which
// is not dialable: the test proves the node learns its real address from peers.
tier::net::Node make_node(tier::core::Role role) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(), role,
                         "0.0.0.0", 0);
}

void codec_roundtrip() {
  const auto enc = tier::core::encode_observed_addr("127.0.0.1:9101");
  const auto dec = tier::core::decode_observed_addr(enc);
  check(dec.has_value(), "observed_addr decodes");
  check(dec && dec->address == "127.0.0.1:9101", "observed_addr round-trips");
  check(tier::core::peek_control_type(enc) ==
            tier::core::ControlType::observed_addr,
        "observed_addr peeks as its type");

  // Truncated (length says 4 bytes, none follow) and trailing-garbage inputs
  // must both be rejected without crashing.
  const std::vector<std::uint8_t> truncated{
      static_cast<std::uint8_t>(tier::core::ControlType::observed_addr), 0x00,
      0x04};
  check(!tier::core::decode_observed_addr(truncated).has_value(),
        "truncated observed_addr rejected");
  std::vector<std::uint8_t> trailing = enc;
  trailing.push_back(0xFF);
  check(!tier::core::decode_observed_addr(trailing).has_value(),
        "observed_addr with trailing byte rejected");
}

}  // namespace

int main() {
  using tier::core::Role;

  codec_roundtrip();

  // Same star bootstrap as the gossip test - B and C only dial the seed A - but
  // here we require an actual full mesh: once B and C learn each other's real
  // (observed) address through A, they dial each other directly. Success means
  // every node holds a live connection to both others, i.e. transitive
  // discovery became transitive connectivity.
  tier::net::Node a = make_node(Role::validator);
  tier::net::Node b = make_node(Role::client);
  tier::net::Node c = make_node(Role::client);

  b.connect("127.0.0.1", a.local_port());
  c.connect("127.0.0.1", a.local_port());

  for (int i = 0; i < 40000 &&
                  !(a.connected_peers().size() == 2 &&
                    b.connected_peers().size() == 2 &&
                    c.connected_peers().size() == 2);
       ++i) {
    a.poll(2);
    b.poll(2);
    c.poll(2);
  }

  check(a.connected_peers().size() == 2, "A connected to both peers");
  check(b.connected_peers().size() == 2, "B connected to both peers");
  check(c.connected_peers().size() == 2, "C connected to both peers");

  // Each node must have replaced its wildcard address with a dialable one.
  for (const auto* n : {&a, &b, &c}) {
    const auto self = n->membership().find(n->peer_id());
    check(self.has_value(), "self entry present");
    bool has_loopback = false;
    bool has_wildcard = false;
    if (self) {
      for (const auto& addr : self->addresses) {
        if (addr.rfind("127.0.0.1:", 0) == 0) {
          has_loopback = true;
        }
        if (addr.rfind("0.0.0.0:", 0) == 0) {
          has_wildcard = true;
        }
      }
    }
    check(has_loopback, "advertised addresses include the observed loopback address");
    check(!has_wildcard, "wildcard address is no longer advertised");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
