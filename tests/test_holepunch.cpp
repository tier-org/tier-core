// Hole punch (see docs/communicator.md, M-NAT). Three parts:
//   1. the signaling codec round-trips and rejects junk;
//   2. the simulated restricted NAT really blocks a one-sided dial (so the test
//      is meaningful);
//   3. with a communicator to coordinate, two NAT'd clients complete a direct
//      connection by a simultaneous open and the message arrives.
#include <cstdio>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/holepunch.hpp"
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

void pump(std::vector<tier::net::Node*> nodes, int n) {
  for (int i = 0; i < n; ++i) {
    for (auto* node : nodes) node->poll(2);
  }
}

tier::crypto::ByteSpan sp(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

void test_codec() {
  using tier::msg::PunchPhase;
  tier::core::PeerId id{};
  id.fill(0x42);
  const std::vector<std::string> addrs = {"10.0.0.1:7777", "[2001:db8::1]:7777"};

  const auto req = tier::msg::make_hole_punch_request(id, PunchPhase::initiate, addrs);
  const auto dreq = tier::msg::open_hole_punch_request(sp(req));
  check(dreq && dreq->target == id && dreq->phase == PunchPhase::initiate &&
            dreq->addresses == addrs,
        "hole_punch_request round-trips");

  const auto sig = tier::msg::make_hole_punch_signal(id, PunchPhase::respond, addrs);
  const auto dsig = tier::msg::open_hole_punch_signal(sp(sig));
  check(dsig && dsig->origin == id && dsig->phase == PunchPhase::respond &&
            dsig->addresses == addrs,
        "hole_punch_signal round-trips");

  // Cross-type and junk are rejected; a truncated frame is rejected.
  check(!tier::msg::open_hole_punch_signal(sp(req)).has_value(),
        "a request does not parse as a signal");
  check(!tier::msg::open_hole_punch_request(tier::crypto::ByteSpan()).has_value(),
        "empty request rejected");
  {
    auto bad = req;
    bad.pop_back();
    check(!tier::msg::open_hole_punch_request(sp(bad)).has_value(),
          "truncated request rejected");
  }
  {
    auto bad = req;
    bad[1 + id.size()] = 0x7F;  // the phase byte -> unknown phase
    check(!tier::msg::open_hole_punch_request(sp(bad)).has_value(),
          "unknown phase rejected");
  }
}

}  // namespace

int main() {
  using tier::core::Role;

  test_codec();

  // --- the simulated NAT must block a one-sided dial ---
  {
    tier::net::Node a = make_node(Role::client);
    tier::net::Node b = make_node(Role::client);
    a.set_simulated_restricted_nat(true);
    b.set_simulated_restricted_nat(true);
    a.connect("127.0.0.1", b.local_port());  // a dials b; b's NAT drops it
    bool connected = false;
    for (int i = 0; i < 1500 && !connected; ++i) {
      pump({&a, &b}, 1);
      for (const auto& p : a.connected_peers()) {
        if (p == b.peer_id()) connected = true;
      }
    }
    check(!connected,
          "a one-sided dial does not connect two restricted-NAT peers");
  }

  // --- with a communicator, the punch connects them and the message arrives ---
  {
    tier::net::Node comm = make_node(Role::communicator);  // not NAT'd (infra)
    tier::net::Node a = make_node(Role::client);
    tier::net::Node b = make_node(Role::client);
    a.set_simulated_restricted_nat(true);
    b.set_simulated_restricted_nat(true);

    // Both clients dial the communicator (outbound, so their NAT admits its
    // replies). The communicator never dials them.
    a.connect("127.0.0.1", comm.local_port());
    b.connect("127.0.0.1", comm.local_port());

    std::vector<tier::net::Node*> all{&comm, &a, &b};
    for (int i = 0; i < 8000 && !(a.has_encryption_keys(comm.peer_id()) &&
                                  b.has_encryption_keys(comm.peer_id()));
         ++i) {
      pump(all, 1);
    }
    check(a.has_encryption_keys(comm.peer_id()) &&
              b.has_encryption_keys(comm.peer_id()),
          "both NAT'd clients reached the communicator");

    // Let presence registration settle so a can resolve b's candidates.
    pump(all, 300);

    const auto pt = bytes("through the NAT, via a hole punch");
    const auto res = a.send_message(b.peer_id(), Suite::hybrid,
                                    std::span<const Byte>(pt.data(), pt.size()));
    check(res == tier::net::Node::SendResult::queued, "send is queued");

    bool got = false;
    for (int i = 0; i < 12000 && !got; ++i) {
      pump(all, 1);
      for (const auto& m : b.take_inbox()) {
        if (m.plaintext == pt) {
          got = true;
          check(m.sender == a.peer_id(), "punched message sender authenticated");
        }
      }
    }
    check(got, "the message arrived over the hole-punched direct connection");
    // The direct connection really exists (not relayed): a holds a connection
    // to b despite both being behind a restricted NAT.
    bool direct = false;
    for (const auto& p : a.connected_peers()) {
      if (p == b.peer_id()) direct = true;
    }
    check(direct, "a holds a direct connection to b after the punch");
  }

  if (g_failures == 0) {
    std::puts("hole punch: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
