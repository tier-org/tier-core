// End-to-end encrypted messaging over two live Nodes: on connect the peers
// exchange signed enc_keys announces, then one sends the other sealed messages
// in each suite and they arrive, decrypted and sender-authenticated, in the
// recipient's inbox.
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

tier::net::Node make_node(tier::core::Role role) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(role), "127.0.0.1", 0);
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

void pump(tier::net::Node& a, tier::net::Node& b, int n) {
  for (int i = 0; i < n; ++i) {
    a.poll(2);
    b.poll(2);
  }
}

// Send a message of `suite` from `from` to `to`, pump, and verify it arrives
// with the right plaintext and authenticated sender.
void send_and_check(tier::net::Node& from, tier::net::Node& to,
                    tier::msg::Suite suite, const std::string& text,
                    const char* name) {
  const auto pt = bytes(text);
  const auto result = from.send_message(to.peer_id(), suite,
                                        std::span<const Byte>(pt.data(), pt.size()));
  // These peers are directly connected with keys exchanged, so the send is
  // immediate, not queued.
  check(result == tier::net::Node::SendResult::sent, name);
  pump(from, to, 200);
  auto inbox = to.take_inbox();
  bool found = false;
  for (const auto& m : inbox) {
    if (m.plaintext == pt) {
      found = true;
      check(m.sender == from.peer_id(), "received message sender authenticated");
      check(m.suite == suite, "received message suite matches");
    }
  }
  check(found, "message delivered to inbox");
}

}  // namespace

int main() {
  using tier::core::Role;
  using tier::msg::Suite;

  // A plain client dials a backbone transmitter. Both announce encryption keys
  // on handshake, so each can message the other over the direct connection.
  tier::net::Node client = make_node(Role::client);
  tier::net::Node backbone = make_node(Role::transmitter);

  client.connect("127.0.0.1", backbone.local_port());

  // Converge: both connected and both holding the other's encryption keys.
  for (int i = 0;
       i < 20000 && !(client.has_encryption_keys(backbone.peer_id()) &&
                      backbone.has_encryption_keys(client.peer_id()));
       ++i) {
    client.poll(2);
    backbone.poll(2);
  }
  check(client.has_encryption_keys(backbone.peer_id()),
        "client learned backbone encryption keys");
  check(backbone.has_encryption_keys(client.peer_id()),
        "backbone learned client encryption keys");

  // Client -> backbone, each suite.
  send_and_check(client, backbone, Suite::classical, "classical hello", "send classical");
  send_and_check(client, backbone, Suite::hybrid, "hybrid hello", "send hybrid");
  send_and_check(client, backbone, Suite::pq, "pq hello", "send pq");

  // Backbone -> client, reverse direction.
  send_and_check(backbone, client, Suite::hybrid, "reply from backbone", "reply hybrid");

  // A larger payload round-trips too.
  send_and_check(client, backbone, Suite::hybrid, std::string(20000, 'x'), "send large");

  // Sending to a peer we are not connected to and cannot resolve (no
  // communicator in this two-node test) is queued, not delivered: it never
  // reaches an inbox and ages out on its own.
  tier::core::PeerId stranger{};
  stranger[0] = 0xAB;
  const std::vector<Byte> p = bytes("nobody");
  const auto res = client.send_message(stranger, Suite::classical,
                                       std::span<const Byte>(p.data(), p.size()));
  check(res == tier::net::Node::SendResult::queued,
        "send to an unresolvable peer is queued, not sent");
  pump(client, backbone, 50);
  for (const auto& m : backbone.take_inbox()) {
    check(m.sender != stranger, "stranger message never delivered");
  }

  if (g_failures == 0) {
    std::puts("messaging e2e: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
