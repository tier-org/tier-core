// Multi-identity end to end (see docs/multi-identity.md). One user is attached
// to two devices; both enroll under the user via a communicator. A separate
// sender, with its own user identity, sends to the user id - and the message
// reaches both of the user's online devices, each authenticated as coming from
// the sender's user id (not merely a device).
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/user.hpp"
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

tier::crypto::NodeIdentity from_same_seed(const tier::crypto::NodeIdentity& id) {
  const auto& s = id.seed();
  return tier::crypto::NodeIdentity::from_seed(
      tier::crypto::ByteSpan(s.data(), s.size()));
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

void pump(std::vector<tier::net::Node*> nodes, int n) {
  for (int i = 0; i < n; ++i) {
    for (auto* node : nodes) {
      node->poll(2);
    }
  }
}

}  // namespace

int main() {
  using tier::core::Role;
  using tier::msg::Suite;

  tier::net::Node comm = make_node(Role::communicator);
  tier::net::Node device1 = make_node(Role::client);
  tier::net::Node device2 = make_node(Role::client);
  tier::net::Node sender = make_node(Role::client);

  // One user on two devices.
  const auto user = tier::crypto::NodeIdentity::generate();
  const auto user_id = tier::msg::user_id_of(user.public_key());
  device1.set_user_identity(from_same_seed(user));
  device2.set_user_identity(from_same_seed(user));

  // The sender has its own distinct user identity.
  const auto sender_user = tier::crypto::NodeIdentity::generate();
  const auto sender_user_id = tier::msg::user_id_of(sender_user.public_key());
  sender.set_user_identity(from_same_seed(sender_user));

  check(device1.user_id() == user_id && device2.user_id() == user_id,
        "both devices share the one user id");
  check(device1.peer_id() != device2.peer_id(),
        "the two devices have distinct device ids");

  // Everyone attaches to the communicator.
  device1.connect("127.0.0.1", comm.local_port());
  device2.connect("127.0.0.1", comm.local_port());
  sender.connect("127.0.0.1", comm.local_port());

  std::vector<tier::net::Node*> all{&comm, &device1, &device2, &sender};

  // Converge: all clients reach the communicator.
  for (int i = 0; i < 8000 &&
                  !(device1.has_encryption_keys(comm.peer_id()) &&
                    device2.has_encryption_keys(comm.peer_id()) &&
                    sender.has_encryption_keys(comm.peer_id()));
       ++i) {
    pump(all, 1);
  }
  check(device1.has_encryption_keys(comm.peer_id()) &&
            device2.has_encryption_keys(comm.peer_id()) &&
            sender.has_encryption_keys(comm.peer_id()),
        "all devices reached the communicator");

  // Let presence + user enrollment settle on the communicator.
  pump(all, 500);

  // Send to the user id, one message per suite in quick succession (as three
  // separate send_to_user calls). Both of the user's online devices must
  // receive all three - this is the case the docker gate exercises.
  struct Msg { Suite suite; std::vector<Byte> pt; };
  const std::vector<Msg> msgs = {
      {Suite::classical, bytes("to-user classical")},
      {Suite::hybrid, bytes("to-user hybrid")},
      {Suite::pq, bytes("to-user pq")},
  };
  for (const auto& m : msgs) {
    const auto res = sender.send_to_user(
        user_id, m.suite, std::span<const Byte>(m.pt.data(), m.pt.size()));
    check(res == tier::net::Node::SendResult::queued, "send_to_user is queued");
  }

  // Track, per device, which of the three payloads have arrived.
  std::vector<bool> got1(msgs.size(), false);
  std::vector<bool> got2(msgs.size(), false);
  auto all_true = [](const std::vector<bool>& v) {
    return std::all_of(v.begin(), v.end(), [](bool b) { return b; });
  };
  auto drain = [&](tier::net::Node& dev, std::vector<bool>& flags) {
    for (const auto& m : dev.take_inbox()) {
      for (std::size_t i = 0; i < msgs.size(); ++i) {
        if (m.plaintext == msgs[i].pt) {
          flags[i] = true;
          check(m.sender_user && *m.sender_user == sender_user_id,
                "sender authenticated as the sender's user id");
        }
      }
    }
  };
  for (int i = 0; i < 8000 && !(all_true(got1) && all_true(got2)); ++i) {
    pump(all, 1);
    drain(device1, got1);
    drain(device2, got2);
  }
  check(all_true(got1), "device 1 received all three user messages");
  check(all_true(got2), "device 2 received all three user messages");

  // A node with no user identity cannot send to a user.
  tier::net::Node plain = make_node(Role::client);
  const auto probe = bytes("x");
  const auto bad = plain.send_to_user(
      user_id, Suite::hybrid, std::span<const Byte>(probe.data(), probe.size()));
  check(bad == tier::net::Node::SendResult::failed,
        "send_to_user without a user identity fails");

  if (g_failures == 0) {
    std::puts("multi-identity e2e: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
