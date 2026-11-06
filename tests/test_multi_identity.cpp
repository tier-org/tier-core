// Multi-identity end to end (see docs/multi-identity.md). Users are hosted on
// nodes at runtime (many per node), messages are sent from one user to another,
// and each delivery is authenticated as coming from the sender's user id and
// routed to the addressed recipient user. Covers: one user on two devices (fan
// out to both), a device that enrolls after the send (resolved repeatedly), two
// users co-resident on one node (local loopback), and the guard that a node
// cannot send as a user it does not host.
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

// User messages are not buffered on the node (online-only): they arrive only
// through on_message_received. This collector stands in for the old inbox - it
// accumulates every delivered message so the checks can scan it.
struct Inbox {
  std::vector<tier::net::Node::ReceivedMessage> msgs;
  void attach(tier::net::Node& n) {
    n.on_message_received(
        [this](const tier::net::Node::ReceivedMessage& m) { msgs.push_back(m); });
  }
};

}  // namespace

int main() {
  using tier::core::Role;
  using tier::msg::Suite;

  // --- co-resident: two users on one node message each other (loopback) ------
  // No communicator, no network: a send from one local user to another local
  // user is delivered straight into the inbox, attributed and addressed.
  {
    tier::net::Node host = make_node(Role::client);
    Inbox host_inbox;
    host_inbox.attach(host);
    const auto alice = host.add_user(tier::crypto::NodeIdentity::generate());
    const auto bob = host.add_user(tier::crypto::NodeIdentity::generate());
    check(host.has_user(alice) && host.has_user(bob), "both users hosted");
    check(host.user_ids().size() == 2, "node reports two hosted users");

    const auto pt = bytes("alice -> bob, same box");
    const auto res = host.send_as_user(
        alice, bob, Suite::hybrid, std::span<const Byte>(pt.data(), pt.size()));
    check(res == tier::net::Node::SendResult::queued, "local send_as_user queued");

    bool got = false;
    for (const auto& m : host_inbox.msgs) {
      if (m.plaintext == pt) {
        got = true;
        check(m.sender_user && *m.sender_user == alice, "loopback sender is alice");
        check(m.recipient_user && *m.recipient_user == bob,
              "loopback recipient is bob");
      }
    }
    check(got, "co-resident user received the loopback message");

    // A node cannot send as a user it does not host.
    tier::net::Node other = make_node(Role::client);
    const auto probe = bytes("x");
    const auto bad = other.send_as_user(
        alice, bob, Suite::hybrid,
        std::span<const Byte>(probe.data(), probe.size()));
    check(bad == tier::net::Node::SendResult::failed,
          "send_as_user from an unhosted user fails");

    // Removing a user: it is no longer hosted.
    check(host.remove_user(alice) && !host.has_user(alice), "user removed");
  }

  // --- one user on two devices, reached over a communicator ------------------
  tier::net::Node comm = make_node(Role::communicator);
  tier::net::Node device1 = make_node(Role::client);
  tier::net::Node device2 = make_node(Role::client);
  tier::net::Node sender = make_node(Role::client);
  Inbox d1_inbox;
  Inbox d2_inbox;
  d1_inbox.attach(device1);
  d2_inbox.attach(device2);

  // One user on two devices (same user seed on both).
  const auto user = tier::crypto::NodeIdentity::generate();
  const auto user_id = device1.add_user(from_same_seed(user));
  const auto user_id2 = device2.add_user(from_same_seed(user));
  check(user_id == user_id2, "both devices host the one user id");
  check(device1.peer_id() != device2.peer_id(),
        "the two devices have distinct device ids");

  // The sender hosts its own distinct user identity.
  const auto sender_user_id =
      sender.add_user(tier::crypto::NodeIdentity::generate());

  // Everyone attaches to the communicator.
  device1.connect("127.0.0.1", comm.local_port());
  device2.connect("127.0.0.1", comm.local_port());
  sender.connect("127.0.0.1", comm.local_port());

  std::vector<tier::net::Node*> all{&comm, &device1, &device2, &sender};

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

  pump(all, 500);  // let presence + user enrollment settle

  // Send to the user id, one message per suite, from the sender's user. Both of
  // the user's online devices must receive all three.
  struct Msg { Suite suite; std::vector<Byte> pt; };
  const std::vector<Msg> msgs = {
      {Suite::classical, bytes("to-user classical")},
      {Suite::hybrid, bytes("to-user hybrid")},
      {Suite::pq, bytes("to-user pq")},
  };
  for (const auto& m : msgs) {
    const auto res = sender.send_as_user(
        sender_user_id, user_id, m.suite,
        std::span<const Byte>(m.pt.data(), m.pt.size()));
    check(res == tier::net::Node::SendResult::queued, "send_as_user is queued");
  }

  std::vector<bool> got1(msgs.size(), false);
  std::vector<bool> got2(msgs.size(), false);
  auto all_true = [](const std::vector<bool>& v) {
    return std::all_of(v.begin(), v.end(), [](bool b) { return b; });
  };
  auto drain = [&](const Inbox& inbox, std::vector<bool>& flags,
                   const tier::core::PeerId& want_recipient) {
    for (const auto& m : inbox.msgs) {
      for (std::size_t i = 0; i < msgs.size(); ++i) {
        if (m.plaintext == msgs[i].pt) {
          flags[i] = true;
          check(m.sender_user && *m.sender_user == sender_user_id,
                "authenticated as the sender's user id");
          check(m.recipient_user && *m.recipient_user == want_recipient,
                "addressed to the recipient user id");
        }
      }
    }
  };
  for (int i = 0; i < 8000 && !(all_true(got1) && all_true(got2)); ++i) {
    pump(all, 1);
    drain(d1_inbox, got1, user_id);
    drain(d2_inbox, got2, user_id);
  }
  check(all_true(got1), "device 1 received all three user messages");
  check(all_true(got2), "device 2 received all three user messages");

  // --- late-enrollment race (regression for the frozen fan-out bug) ----------
  // A device that enrolls under the user AFTER a send has already been resolved
  // to the other devices must still receive it: the recipient's device set is
  // resolved repeatedly within the send window, not frozen at the first result.
  tier::net::Node device3 = make_node(Role::client);
  Inbox d3_inbox;
  d3_inbox.attach(device3);
  device3.add_user(from_same_seed(user));
  const auto late_pt = bytes("to-user late-enroll");
  {
    const auto res = sender.send_as_user(
        sender_user_id, user_id, Suite::classical,
        std::span<const Byte>(late_pt.data(), late_pt.size()));
    check(res == tier::net::Node::SendResult::queued,
          "late-enroll send_as_user is queued");
  }
  pump(all, 80);  // resolve + fan out to the devices known so far (not device3)
  device3.connect("127.0.0.1", comm.local_port());
  std::vector<tier::net::Node*> all3{&comm, &device1, &device2, &sender, &device3};
  bool got3 = false;
  for (int i = 0; i < 20000 && !got3; ++i) {
    pump(all3, 1);
    for (const auto& m : d3_inbox.msgs) {
      if (m.plaintext == late_pt) {
        got3 = true;
        check(m.sender_user && *m.sender_user == sender_user_id,
              "late device: authenticated as the sender's user id");
      }
    }
  }
  check(got3, "a device enrolling after the send still receives it");

  if (g_failures == 0) {
    std::puts("multi-identity e2e: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
