// Multi-identity end to end (see docs/multi-identity.md). Users are hosted on
// nodes at runtime (many per node), messages are sent from one user to another,
// and each delivery is authenticated as coming from the sender's user id and
// routed to the addressed recipient user. Covers: one user on two devices (fan
// out to both), a device that enrolls after the send (resolved repeatedly), two
// users co-resident on one node (local loopback), and the guard that a node
// cannot send as a user it does not host.
#include <algorithm>
#include <cstdio>
#include <memory>
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
    // Online = a client is subscribed; the Node tests stand in for that hub by
    // marking hosted users present so they enroll and become addressable.
    host.set_user_presence(alice, true);
    host.set_user_presence(bob, true);
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
  device1.set_user_presence(user_id, true);
  device2.set_user_presence(user_id2, true);
  check(user_id == user_id2, "both devices host the one user id");
  check(device1.peer_id() != device2.peer_id(),
        "the two devices have distinct device ids");

  // The sender hosts its own distinct user identity.
  const auto sender_user_id =
      sender.add_user(tier::crypto::NodeIdentity::generate());
  sender.set_user_presence(sender_user_id, true);

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
  device3.set_user_presence(user_id, true);
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

  // --- regression: a node that is itself a responsible communicator for its
  // own hosted user. In production every node holds the communicator role and
  // also hosts users, so a user frequently rendezvous-maps onto its own host.
  // The directory enroll/resolve paths only talked to *remote* responsible
  // communicators: the self replica was never written on enroll nor consulted
  // on resolve, so such a user could not be reached from the nodes that needed
  // that replica (messages and delivery receipts silently failed one way). Two
  // all-role nodes, each hosting a user, must message each other both ways. ----
  {
    tier::net::Node na(tier::crypto::NodeIdentity::generate(),
                       tier::core::kAllRoles, "127.0.0.1", 0);
    tier::net::Node nb(tier::crypto::NodeIdentity::generate(),
                       tier::core::kAllRoles, "127.0.0.1", 0);
    Inbox ia;
    Inbox ib;
    ia.attach(na);
    ib.attach(nb);
    const auto ua = na.add_user(tier::crypto::NodeIdentity::generate());
    const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
    na.set_user_presence(ua, true);
    nb.set_user_presence(ub, true);

    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};
    for (int i = 0; i < 8000 && !(na.has_encryption_keys(nb.peer_id()) &&
                                  nb.has_encryption_keys(na.peer_id()));
         ++i) {
      pump(both, 1);
    }
    check(na.has_encryption_keys(nb.peer_id()) &&
              nb.has_encryption_keys(na.peer_id()),
          "two all-role nodes meshed");
    pump(both, 500);  // let user enrollment settle on both directories

    const auto pa = bytes("A->B hello");
    const auto pb = bytes("B->A hello");
    check(na.send_as_user(ua, ub, Suite::hybrid,
                          std::span<const Byte>(pa.data(), pa.size())) ==
              tier::net::Node::SendResult::queued,
          "A->B send_as_user queued");
    check(nb.send_as_user(ub, ua, Suite::hybrid,
                          std::span<const Byte>(pb.data(), pb.size())) ==
              tier::net::Node::SendResult::queued,
          "B->A send_as_user queued");

    bool a_to_b = false;
    bool b_to_a = false;
    for (int i = 0; i < 20000 && !(a_to_b && b_to_a); ++i) {
      pump(both, 1);
      for (const auto& m : ib.msgs) {
        if (m.plaintext == pa && m.sender_user && *m.sender_user == ua &&
            m.recipient_user && *m.recipient_user == ub) {
          a_to_b = true;
        }
      }
      for (const auto& m : ia.msgs) {
        if (m.plaintext == pb && m.sender_user && *m.sender_user == ub &&
            m.recipient_user && *m.recipient_user == ua) {
          b_to_a = true;
        }
      }
    }
    check(a_to_b, "A->B delivered (host is itself a responsible communicator)");
    check(b_to_a, "B->A delivered (self directory replica is consulted)");
  }

  // --- cross-node presence: a watcher must see a host's user go offline once
  // the host de-enrolls it, i.e. the remote directory replica is cleared (not
  // just the host's local present flag). Regression for a badge that stuck on
  // "online" after the client closed. ----
  {
    tier::net::Node na(tier::crypto::NodeIdentity::generate(),
                       tier::core::kAllRoles, "127.0.0.1", 0);
    tier::net::Node nb(tier::crypto::NodeIdentity::generate(),
                       tier::core::kAllRoles, "127.0.0.1", 0);
    const auto ua = na.add_user(tier::crypto::NodeIdentity::generate());
    na.set_user_presence(ua, true);
    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};
    for (int i = 0; i < 8000 && !(na.has_encryption_keys(nb.peer_id()) &&
                                  nb.has_encryption_keys(na.peer_id()));
         ++i) {
      pump(both, 1);
    }
    pump(both, 500);  // let ua's enrollment reach nb's directory
    // nb watches ua and must resolve it online.
    auto seen = nb.query_user_presence(ua);
    for (int i = 0; i < 500 && seen != tier::net::Node::Presence::online; ++i) {
      pump(both, 1);
      seen = nb.query_user_presence(ua);
    }
    check(seen == tier::net::Node::Presence::online,
          "watcher resolves a remote host's user as online");
    // ua goes offline on its host; the de-enroll must clear nb's replica.
    na.set_user_presence(ua, false);
    bool offline = false;
    for (int i = 0; i < 2000; ++i) {
      pump(both, 1);
      if (nb.query_user_presence(ua) == tier::net::Node::Presence::offline) {
        offline = true;
        break;
      }
    }
    check(offline, "watcher sees the user offline after the host de-enrolls it");
  }

  // --- production-shaped topology: N all-role nodes meshed, each hosting a
  // user, every ordered pair must deliver. This is what the deployed network
  // actually looks like (every node holds every role and hosts users), and the
  // directory self-replica bug hid precisely because no test ran this shape -
  // the earlier tests use a dedicated communicator plus single-role hosts. ----
  {
    constexpr std::size_t kN = 3;
    std::vector<std::unique_ptr<tier::net::Node>> nodes;
    std::vector<Inbox> inbox(kN);
    std::vector<tier::core::PeerId> uid(kN);
    for (std::size_t i = 0; i < kN; ++i) {
      nodes.push_back(std::make_unique<tier::net::Node>(
          tier::crypto::NodeIdentity::generate(), tier::core::kAllRoles,
          "127.0.0.1", 0));
    }
    std::vector<tier::net::Node*> mesh;
    for (std::size_t i = 0; i < kN; ++i) {
      mesh.push_back(nodes[i].get());
      inbox[i].attach(*nodes[i]);
      uid[i] = nodes[i]->add_user(tier::crypto::NodeIdentity::generate());
      nodes[i]->set_user_presence(uid[i], true);
    }
    // Full mesh: connect every pair so each node learns every other.
    for (std::size_t i = 0; i < kN; ++i) {
      for (std::size_t j = i + 1; j < kN; ++j) {
        nodes[i]->connect("127.0.0.1", nodes[j]->local_port());
      }
    }
    auto all_meshed = [&] {
      for (std::size_t i = 0; i < kN; ++i) {
        for (std::size_t j = 0; j < kN; ++j) {
          if (i != j && !nodes[i]->has_encryption_keys(nodes[j]->peer_id())) {
            return false;
          }
        }
      }
      return true;
    };
    for (int i = 0; i < 12000 && !all_meshed(); ++i) {
      pump(mesh, 1);
    }
    check(all_meshed(), "all-role nodes formed a full mesh");
    pump(mesh, 400);  // let every user enroll on its responsible communicators

    // Every ordered (sender user -> recipient user) pair, distinct hosts.
    struct Pair { std::size_t from; std::size_t to; std::vector<Byte> pt; };
    std::vector<Pair> pairs;
    for (std::size_t a = 0; a < kN; ++a) {
      for (std::size_t b = 0; b < kN; ++b) {
        if (a == b) {
          continue;
        }
        pairs.push_back({a, b,
                         bytes("u" + std::to_string(a) + "->u" +
                               std::to_string(b))});
      }
    }
    for (const auto& p : pairs) {
      check(nodes[p.from]->send_as_user(
                uid[p.from], uid[p.to], Suite::hybrid,
                std::span<const Byte>(p.pt.data(), p.pt.size())) ==
                tier::net::Node::SendResult::queued,
            "all-role pair send_as_user queued");
    }
    auto all_delivered = [&] {
      for (const auto& p : pairs) {
        bool got = false;
        for (const auto& m : inbox[p.to].msgs) {
          if (m.plaintext == p.pt && m.sender_user && *m.sender_user == uid[p.from] &&
              m.recipient_user && *m.recipient_user == uid[p.to]) {
            got = true;
            break;
          }
        }
        if (!got) {
          return false;
        }
      }
      return true;
    };
    for (int i = 0; i < 20000 && !all_delivered(); ++i) {
      pump(mesh, 1);
    }
    check(all_delivered(),
          "every ordered user pair delivered across the all-role mesh");
  }

  // --- presence: online/offline gating (docs/multi-identity.md) --------------
  // A user is addressable only while it has a live subscriber; set_user_presence
  // stands in for the subscriber hub. A send to an offline user is refused
  // (recipient_offline) instead of silently dropped, and query_user_presence
  // reports the status the messenger shows.
  {
    using Presence = tier::net::Node::Presence;
    using SendResult = tier::net::Node::SendResult;

    // Co-resident: exact and synchronous (a node knows its own users' presence).
    {
      tier::net::Node host = make_node(Role::client);
      Inbox hi;
      hi.attach(host);
      const auto ua = host.add_user(tier::crypto::NodeIdentity::generate());
      const auto ub = host.add_user(tier::crypto::NodeIdentity::generate());
      host.set_user_presence(ua, true);  // ub is left offline
      const auto p = bytes("to local user");
      check(host.send_as_user(ua, ub, Suite::hybrid,
                              std::span<const Byte>(p.data(), p.size())) ==
                SendResult::recipient_offline,
            "co-resident send to an offline user is refused");
      check(host.query_user_presence(ub) == Presence::offline,
            "local offline user reads offline");
      host.set_user_presence(ub, true);
      check(host.query_user_presence(ub) == Presence::online,
            "local online user reads online");
      check(host.send_as_user(ua, ub, Suite::hybrid,
                              std::span<const Byte>(p.data(), p.size())) ==
                SendResult::queued,
            "co-resident send to an online user is accepted");
      bool got = false;
      for (int i = 0; i < 300 && !got; ++i) {
        host.poll(2);
        for (const auto& m : hi.msgs) {
          if (m.plaintext == p && m.recipient_user && *m.recipient_user == ub) {
            got = true;
          }
        }
      }
      check(got, "co-resident online delivery (loopback) works");
    }

    // Cross-node: presence flows through the directory - offline refuses, online
    // delivers, going offline again refuses once more.
    {
      tier::net::Node na(tier::crypto::NodeIdentity::generate(),
                         tier::core::kAllRoles, "127.0.0.1", 0);
      tier::net::Node nb(tier::crypto::NodeIdentity::generate(),
                         tier::core::kAllRoles, "127.0.0.1", 0);
      Inbox ib;
      ib.attach(nb);
      const auto ua = na.add_user(tier::crypto::NodeIdentity::generate());
      const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
      na.set_user_presence(ua, true);  // ub starts offline (no subscriber)
      na.connect("127.0.0.1", nb.local_port());
      std::vector<tier::net::Node*> both{&na, &nb};
      for (int i = 0; i < 8000 && !(na.has_encryption_keys(nb.peer_id()) &&
                                    nb.has_encryption_keys(na.peer_id()));
           ++i) {
        pump(both, 1);
      }
      check(na.has_encryption_keys(nb.peer_id()), "presence: nodes meshed");

      const auto settle_presence = [&](Presence want) {
        for (int i = 0; i < 6000; ++i) {
          pump(both, 1);
          if (na.query_user_presence(ub) == want) {
            return true;
          }
        }
        return false;
      };

      check(settle_presence(Presence::offline),
            "remote offline user resolves to offline");
      const auto p1 = bytes("to offline remote");
      check(na.send_as_user(ua, ub, Suite::hybrid,
                            std::span<const Byte>(p1.data(), p1.size())) ==
                SendResult::recipient_offline,
            "cross-node send to an offline user is refused");

      nb.set_user_presence(ub, true);
      check(settle_presence(Presence::online),
            "remote user resolves to online once a subscriber attaches");
      const auto p2 = bytes("to online remote");
      check(na.send_as_user(ua, ub, Suite::hybrid,
                            std::span<const Byte>(p2.data(), p2.size())) ==
                SendResult::queued,
            "cross-node send to an online user is accepted");
      bool delivered = false;
      for (int i = 0; i < 20000 && !delivered; ++i) {
        pump(both, 1);
        for (const auto& m : ib.msgs) {
          if (m.plaintext == p2 && m.recipient_user && *m.recipient_user == ub) {
            delivered = true;
          }
        }
      }
      check(delivered, "cross-node online delivery works");

      nb.set_user_presence(ub, false);
      check(settle_presence(Presence::offline),
            "remote user resolves back to offline after de-enroll");
      const auto p3 = bytes("to offline again");
      check(na.send_as_user(ua, ub, Suite::hybrid,
                            std::span<const Byte>(p3.data(), p3.size())) ==
                SendResult::recipient_offline,
            "cross-node send after going offline is refused again");
    }
  }

  if (g_failures == 0) {
    std::puts("multi-identity e2e: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
