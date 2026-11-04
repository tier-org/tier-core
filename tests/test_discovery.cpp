// Client-to-client discovery over live Nodes (see docs/communicator.md). Two
// edge clients that never gossip each other and share no prior connection reach
// each other through a communicator: one publishes a presence record, the other
// resolves it by a presence lookup, connects directly, and the sealed message
// arrives. Exercises all three suites and both directions.
#include <cstdio>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/sealed.hpp"
#include "tier/net/node.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::crypto::Byte;
using tier::msg::Suite;

tier::net::Node make_node(tier::core::Role role) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(role), "127.0.0.1", 0);
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

void pump3(tier::net::Node& a, tier::net::Node& b, tier::net::Node& c, int n) {
  for (int i = 0; i < n; ++i) {
    a.poll(2);
    b.poll(2);
    c.poll(2);
  }
}

// Send from `from` to `to` by id (no prior direct connection required), pumping
// the whole little network until it arrives or we give up.
void send_and_expect(tier::net::Node& from, tier::net::Node& to,
                     tier::net::Node& comm, Suite suite,
                     const std::string& text, const char* name) {
  const auto pt = bytes(text);
  const auto res = from.send_message(
      to.peer_id(), suite, std::span<const Byte>(pt.data(), pt.size()));
  // Either already connected (sent) or resolved via the communicator (queued).
  check(res == tier::net::Node::SendResult::sent ||
            res == tier::net::Node::SendResult::queued,
        name);

  bool found = false;
  for (int i = 0; i < 4000 && !found; ++i) {
    pump3(from, to, comm, 1);
    for (const auto& m : to.take_inbox()) {
      if (m.plaintext == pt) {
        found = true;
        check(m.sender == from.peer_id(), "discovered message sender authenticated");
        check(m.suite == suite, "discovered message suite matches");
      }
    }
  }
  check(found, name);
}

}  // namespace

int main() {
  using tier::core::Role;

  // A communicator and two edge clients. Each client dials the communicator
  // (infrastructure); the clients never dial or gossip each other.
  tier::net::Node comm = make_node(Role::communicator);
  tier::net::Node a = make_node(Role::client);
  tier::net::Node b = make_node(Role::client);

  a.connect("127.0.0.1", comm.local_port());
  b.connect("127.0.0.1", comm.local_port());

  // Converge: both clients connected to the communicator and each holding its
  // keys (handshake complete), and the communicator knows both.
  for (int i = 0;
       i < 8000 && !(a.has_encryption_keys(comm.peer_id()) &&
                     b.has_encryption_keys(comm.peer_id()));
       ++i) {
    a.poll(2);
    b.poll(2);
    comm.poll(2);
  }
  check(a.has_encryption_keys(comm.peer_id()), "client A reached the communicator");
  check(b.has_encryption_keys(comm.peer_id()), "client B reached the communicator");

  // Neither client knows the other yet: a plain client is not gossiped.
  check(!a.has_encryption_keys(b.peer_id()),
        "A does not know B before discovery");
  check(!b.has_encryption_keys(a.peer_id()),
        "B does not know A before discovery");

  // Let presence registration settle (clients publish to the communicator).
  pump3(a, b, comm, 400);

  // A -> B by id, resolved through the communicator, in each suite.
  send_and_expect(a, b, comm, Suite::classical, "c2c classical", "A->B classical");
  send_and_expect(a, b, comm, Suite::hybrid, "c2c hybrid", "A->B hybrid");
  send_and_expect(a, b, comm, Suite::pq, "c2c pq", "A->B pq");

  // B -> A as well (now likely a direct connection already exists, so this also
  // covers the immediate-send path after discovery).
  send_and_expect(b, a, comm, Suite::hybrid, "c2c reverse", "B->A hybrid");

  // A larger payload across the discovered connection.
  send_and_expect(a, b, comm, Suite::hybrid, std::string(20000, 'z'),
                  "A->B large");

  if (g_failures == 0) {
    std::puts("discovery e2e: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
