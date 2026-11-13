// Fault-injection / adverse-network tests (see Endpoint::set_link_loss). The
// other end-to-end tests run on a clean loopback link; these degrade a node's
// link with seeded packet loss and full partitions, which is what a `client`
// role on bad internet actually experiences, and assert the system's safety and
// liveness invariants still hold:
//
//   Safety (must hold even under loss): a delivered message carries the right
//   sender and recipient user ids - loss never misroutes or misattributes.
//
//   Liveness (must hold once the network can make progress): a message sent over
//   a lossy link still gets delivered (QUIC loss recovery carries it); presence
//   converges to the truth - online while a host refreshes its lease, offline
//   after it stops, even when the explicit de-enroll cannot be sent because the
//   host is fully partitioned (the short lease is the floor); and it recovers to
//   online once the link heals.
//
//   Robustness: sustained loss plus rapid online/offline churn neither crashes
//   nor leaks (run under ASan) and still converges at the end.
//
// Loss is applied with a fixed seed so a failure reproduces exactly. Budgets are
// wall-clock deadlines, generous because QUIC retransmission and the 20s presence
// lease are real-time; a pass well inside the budget is the normal case.
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "tier/crypto/identity.hpp"
#include "tier/msg/user.hpp"
#include "tier/net/node.hpp"

namespace {

using tier::crypto::Byte;
using Clock = std::chrono::steady_clock;

int g_failures = 0;

void check(bool ok, const char* what) {
  std::fprintf(stderr, "%s: %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) {
    ++g_failures;
  }
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

void pump(const std::vector<tier::net::Node*>& nodes, int n) {
  for (int i = 0; i < n; ++i) {
    for (auto* node : nodes) {
      node->poll(2);
    }
  }
}

// Pump the nodes until `cond` holds or `max_ms` of wall time elapses. Returns
// whether it held, and reports how long it took so a convergence time is visible
// in the test output.
bool pump_until(const std::vector<tier::net::Node*>& nodes,
                const std::function<bool()>& cond, int max_ms,
                const char* label) {
  const auto start = Clock::now();
  const auto deadline = start + std::chrono::milliseconds(max_ms);
  while (Clock::now() < deadline) {
    pump(nodes, 1);
    if (cond()) {
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          Clock::now() - start)
                          .count();
      std::fprintf(stderr, "     (%s converged in %lldms)\n", label,
                   static_cast<long long>(ms));
      return true;
    }
  }
  return cond();
}

tier::net::Node all_role_node() {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::kAllRoles, "127.0.0.1", 0);
}

bool meshed(tier::net::Node& a, tier::net::Node& b) {
  return a.has_encryption_keys(b.peer_id()) &&
         b.has_encryption_keys(a.peer_id());
}

bool got(const std::vector<tier::net::Node::ReceivedMessage>& box,
         const std::vector<Byte>& body, const tier::core::PeerId& from_user,
         const tier::core::PeerId& to_user) {
  for (const auto& m : box) {
    if (m.plaintext == body && m.sender_user && *m.sender_user == from_user &&
        m.recipient_user && *m.recipient_user == to_user) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  using tier::msg::Suite;
  using Presence = tier::net::Node::Presence;
  using SendResult = tier::net::Node::SendResult;

  // === 1. Handshake AND delivery under 15% loss from the very start ==========
  // A client on a bad link must be able to join and exchange messages, not just
  // once already connected. Loss is on before the first packet.
  {
    std::fprintf(stderr, "\n[1] join + deliver under 15%% loss from the start\n");
    tier::net::Node na = all_role_node();
    tier::net::Node nb = all_role_node();
    na.set_link_loss(0.15, 0xA1);
    nb.set_link_loss(0.15, 0xB1);
    std::vector<tier::net::Node::ReceivedMessage> ia;
    std::vector<tier::net::Node::ReceivedMessage> ib;
    na.on_message_received([&](const auto& m) { ia.push_back(m); });
    nb.on_message_received([&](const auto& m) { ib.push_back(m); });
    const auto ua = na.add_user(tier::crypto::NodeIdentity::generate());
    const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
    na.set_user_presence(ua, true);
    nb.set_user_presence(ub, true);
    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};

    check(pump_until(both, [&] { return meshed(na, nb); }, 20000, "handshake"),
          "two nodes complete the QUIC handshake despite 15% loss");
    pump(both, 400);  // let the user leases reach both directories

    const auto pa = bytes("A->B over a lossy link");
    const auto pb = bytes("B->A over a lossy link");
    check(na.send_as_user(ua, ub, Suite::hybrid,
                          std::span<const Byte>(pa.data(), pa.size())) ==
              SendResult::queued,
          "A->B accepted");
    check(nb.send_as_user(ub, ua, Suite::hybrid,
                          std::span<const Byte>(pb.data(), pb.size())) ==
              SendResult::queued,
          "B->A accepted");
    check(pump_until(
              both, [&] { return got(ib, pa, ua, ub) && got(ia, pb, ub, ua); },
              20000, "delivery"),
          "both messages delivered under loss, correctly attributed/addressed");
  }

  // === 2. Presence converges under 20% loss (de-enroll still lands) ==========
  // The de-enroll travels on a reliable QUIC stream, so loss only slows it; the
  // watcher must still see the user go offline promptly, then online again.
  {
    std::fprintf(stderr, "\n[2] presence online->offline->online under 20%% loss\n");
    tier::net::Node na = all_role_node();  // watcher
    tier::net::Node nb = all_role_node();  // host of the watched user
    const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
    nb.set_user_presence(ub, true);
    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};
    check(pump_until(both, [&] { return meshed(na, nb); }, 15000, "handshake"),
          "nodes meshed");
    pump(both, 400);
    // Degrade the host's link only now, so this isolates presence-under-loss.
    nb.set_link_loss(0.20, 0x2B);

    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::online; },
              15000, "online"),
          "watcher resolves the user online under loss");
    nb.set_user_presence(ub, false);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::offline; },
              25000, "offline"),
          "watcher sees offline after de-enroll (even slowed by loss)");
    nb.set_user_presence(ub, true);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::online; },
              15000, "re-online"),
          "watcher sees the user online again after it returns");
  }

  // === 3. Full partition of the host: offline via the lease, recover on heal ==
  // The hard case the earlier design missed: the host is cut off entirely (its
  // node died or lost the network), so NO de-enroll can ever be sent. Presence
  // must still fall to offline on its own once the enrollment lease lapses, and
  // come back once the link heals. This is the self-healing floor; it takes on
  // the order of the lease TTL (~20s), so the budget is deliberately large.
  {
    std::fprintf(stderr, "\n[3] host fully partitioned: lease expiry -> offline, then heal\n");
    tier::net::Node na = all_role_node();  // watcher
    tier::net::Node nb = all_role_node();  // host, about to be partitioned
    const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
    nb.set_user_presence(ub, true);
    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};
    check(pump_until(both, [&] { return meshed(na, nb); }, 15000, "handshake"),
          "nodes meshed");
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::online; },
              15000, "online"),
          "watcher resolves the user online before the partition");

    // Cut the host off completely (no packet in or out) - it cannot de-enroll.
    nb.set_link_loss(1.0, 0x3B);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::offline; },
              30000, "lease-expiry-offline"),
          "watcher falls to offline via lease expiry with no de-enroll possible");

    // Heal the link: the host resumes refreshing its lease; presence recovers.
    nb.set_link_loss(0.0, 0x3C);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::online; },
              20000, "recover-online"),
          "watcher recovers to online after the link heals");
  }

  // === 4. Churn + loss soak: no crash/leak (ASan), converges at the end =======
  // Rapid online/offline flips plus sends under sustained 10% loss. The point is
  // robustness - no UB, no leak, no deadlock - plus a final convergence check.
  {
    std::fprintf(stderr, "\n[4] churn + 10%% loss soak\n");
    tier::net::Node na = all_role_node();
    tier::net::Node nb = all_role_node();
    std::vector<tier::net::Node::ReceivedMessage> ib;
    nb.on_message_received([&](const auto& m) { ib.push_back(m); });
    const auto ua = na.add_user(tier::crypto::NodeIdentity::generate());
    const auto ub = nb.add_user(tier::crypto::NodeIdentity::generate());
    na.set_user_presence(ua, true);
    nb.set_user_presence(ub, true);
    na.connect("127.0.0.1", nb.local_port());
    std::vector<tier::net::Node*> both{&na, &nb};
    check(pump_until(both, [&] { return meshed(na, nb); }, 15000, "handshake"),
          "nodes meshed");
    pump(both, 300);
    na.set_link_loss(0.10, 0x41);
    nb.set_link_loss(0.10, 0x42);

    for (int i = 0; i < 24; ++i) {
      nb.set_user_presence(ub, (i % 2) == 0);  // flap the watched user
      const auto p = bytes("churn-" + std::to_string(i));
      (void)na.send_as_user(ua, ub, Suite::hybrid,
                            std::span<const Byte>(p.data(), p.size()));
      (void)na.query_user_presence(ub);  // keep resolving through the churn
      pump(both, 120);
    }
    // Settle to a known state and confirm presence converges after the storm.
    nb.set_link_loss(0.0, 0x43);
    na.set_link_loss(0.0, 0x44);
    nb.set_user_presence(ub, true);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::online; },
              15000, "settle-online"),
          "presence converges online after churn + loss");
    nb.set_user_presence(ub, false);
    check(pump_until(
              both, [&] { return na.query_user_presence(ub) == Presence::offline; },
              25000, "settle-offline"),
          "presence converges offline after churn + loss");
  }

  if (g_failures == 0) {
    std::fprintf(stderr, "\nfault-injection: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "\nfault-injection: %d check(s) failed\n", g_failures);
  return 1;
}
