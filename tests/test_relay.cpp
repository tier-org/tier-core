// Relay fallback (see docs/communicator.md, M-NAT). Three parts:
//   1. the relay-envelope codec round-trips and rejects junk;
//   2. two clients behind a simulated symmetric NAT (where a hole punch cannot
//      land) still exchange a message - it is routed through the communicator
//      as ciphertext, authenticated end-to-end, and no direct connection forms;
//   3. a second message to the same peer also arrives (the relay path is not a
//      one-shot: resolution stays cached so a repeat send relays promptly).
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "tier/core/control.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/holepunch.hpp"
#include "tier/msg/relay.hpp"
#include "tier/msg/sealed.hpp"
#include "tier/net/endpoint.hpp"
#include "tier/net/node.hpp"

namespace {

using tier::crypto::Byte;
using tier::msg::Suite;
using Clock = std::chrono::steady_clock;

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<Byte> bytes(const std::string& s) {
  return std::vector<Byte>(s.begin(), s.end());
}

tier::crypto::ByteSpan sp(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

tier::net::Node make_node(tier::core::Role role) {
  return tier::net::Node(tier::crypto::NodeIdentity::generate(),
                         tier::core::role_bit(role), "127.0.0.1", 0);
}

tier::core::PeerId id_of(const tier::crypto::NodeIdentity& id) {
  const auto& pub = id.public_key();
  const auto d = tier::crypto::sha256(tier::crypto::ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId p{};
  for (std::size_t i = 0; i < p.size(); ++i) p[i] = d[i];
  return p;
}

tier::msg::Recipient recipient_of(const tier::crypto::NodeIdentity& id) {
  tier::msg::Recipient r;
  r.id = id_of(id);
  r.keys.x25519 = id.x25519_identity_key().public_key;
  r.keys.mlkem = id.mlkem768_identity_key().public_key;
  return r;
}

// Drive a bare endpoint's handshake with `node`, returning the endpoint's
// connection id to it. A bare Endpoint lets a test inject a raw, hand-crafted
// frame the normal send path would never emit.
tier::net::ConnId handshake_with(tier::net::Endpoint& ep, tier::net::Node& node) {
  tier::net::ConnId conn = 0;
  bool done = false;
  ep.on_handshake([&](tier::net::ConnId c, bool, const tier::net::PeerId&) {
    conn = c;
    done = true;
  });
  ep.connect("127.0.0.1", node.local_port());
  for (int i = 0; i < 4000 && !done; ++i) {
    ep.poll(2);
    node.poll(2);
  }
  return conn;
}

void pump(const std::vector<tier::net::Node*>& nodes, int n) {
  for (int i = 0; i < n; ++i) {
    for (auto* node : nodes) node->poll(2);
  }
}

// Pump until `cond` holds or `max_ms` of wall time elapses. The relay fallback
// is driven by real-time graces (direct-dial + punch before it concedes), so
// the deadline is wall-clock, not an iteration count.
bool pump_until(const std::vector<tier::net::Node*>& nodes,
                const std::function<bool()>& cond, int max_ms) {
  const auto deadline = Clock::now() + std::chrono::milliseconds(max_ms);
  while (Clock::now() < deadline) {
    pump(nodes, 1);
    if (cond()) return true;
  }
  return cond();
}

void test_codec() {
  using tier::msg::make_relay_frame;
  using tier::msg::open_relay_frame;
  tier::core::PeerId dst{};
  dst.fill(0x11);
  tier::crypto::Ed25519PublicKey src{};
  src.fill(0x22);
  const auto sealed = bytes("opaque sealed blob");

  const auto frame = make_relay_frame(dst, src, sp(sealed));
  const auto dec = open_relay_frame(sp(frame));
  check(dec && dec->dst == dst && dec->src_key == src &&
            std::vector<Byte>(dec->sealed.begin(), dec->sealed.end()) == sealed,
        "relay_frame round-trips");

  // An empty sealed blob is a valid (if useless) frame: header only.
  const auto empty = make_relay_frame(dst, src, tier::crypto::ByteSpan());
  const auto dec_empty = open_relay_frame(sp(empty));
  check(dec_empty && dec_empty->sealed.empty(),
        "relay_frame with empty payload round-trips");

  // Junk and a frame too short to hold the fixed header are rejected.
  check(!open_relay_frame(tier::crypto::ByteSpan()).has_value(),
        "empty message rejected");
  {
    auto bad = frame;
    bad.resize(10);  // shorter than 1 + 32 + 32
    check(!open_relay_frame(sp(bad)).has_value(), "truncated header rejected");
  }
  {
    // A hole-punch frame (different type tag) must not parse as a relay frame.
    tier::core::PeerId id{};
    id.fill(0x42);
    const auto hp = tier::msg::make_hole_punch_request(
        id, tier::msg::PunchPhase::initiate, {"10.0.0.1:7777"});
    check(!open_relay_frame(sp(hp)).has_value(),
          "a hole-punch frame does not parse as a relay frame");
  }
}

}  // namespace

int main() {
  using tier::core::Role;

  test_codec();

  // --- symmetric NAT: punch cannot land, but the relay delivers ---
  {
    tier::net::Node comm = make_node(Role::communicator);  // infra, not NAT'd
    tier::net::Node a = make_node(Role::client);
    tier::net::Node b = make_node(Role::client);
    a.set_simulated_symmetric_nat(true);
    b.set_simulated_symmetric_nat(true);

    // Both clients dial the communicator (outbound, admitted by their NAT). The
    // communicator never dials them, and they can never reach each other.
    a.connect("127.0.0.1", comm.local_port());
    b.connect("127.0.0.1", comm.local_port());
    std::vector<tier::net::Node*> all{&comm, &a, &b};

    check(pump_until(all,
                     [&] {
                       return a.has_encryption_keys(comm.peer_id()) &&
                              b.has_encryption_keys(comm.peer_id());
                     },
                     15000),
          "both symmetric-NAT clients reached the communicator");
    pump(all, 300);  // let presence registration settle

    const auto pt = bytes("delivered through a relay, not a punch");
    check(a.send_message(b.peer_id(), Suite::hybrid, sp(pt)) ==
              tier::net::Node::SendResult::queued,
          "send is queued");

    bool got = false;
    const bool arrived = pump_until(
        all,
        [&] {
          for (const auto& m : b.take_inbox()) {
            if (m.plaintext == pt) {
              got = true;
              check(m.sender == a.peer_id(),
                    "relayed message sender authenticated end-to-end");
            }
          }
          return got;
        },
        30000);
    check(arrived, "the message arrived over the relay fallback");

    // It really went through the relay, not a punched direct connection.
    bool direct = false;
    for (const auto& p : a.connected_peers()) {
      if (p == b.peer_id()) direct = true;
    }
    check(!direct, "no direct connection to the peer formed (relay, not punch)");

    // A second message to the same peer also arrives, and promptly (resolution
    // stayed cached, so it does not re-run the full punch grace).
    const auto pt2 = bytes("second message, still over the relay");
    check(a.send_message(b.peer_id(), Suite::hybrid, sp(pt2)) ==
              tier::net::Node::SendResult::queued,
          "second send is queued");
    bool got2 = false;
    const bool arrived2 = pump_until(
        all,
        [&] {
          for (const auto& m : b.take_inbox()) {
            if (m.plaintext == pt2) got2 = true;
          }
          return got2;
        },
        15000);
    check(arrived2, "the second message also arrived over the relay");
  }

  // --- forward-gate: a non-communicator does not forward a relay frame ---
  // Only a communicator relays. A plain client that receives a relay_data frame
  // addressed to someone else must drop it, never forward it - otherwise any
  // node could be turned into an open relay.
  {
    tier::net::Node m = make_node(Role::client);  // NOT a communicator
    const auto target_identity = tier::crypto::NodeIdentity::generate();
    const auto target_id = id_of(target_identity);

    // A bare endpoint standing in for the target, so we can observe exactly what
    // m sends it - including whether m forwards the relay frame.
    tier::net::Endpoint target_ep(target_identity, "127.0.0.1", 0);
    int relay_forwards_seen = 0;
    target_ep.on_message([&](tier::net::ConnId, const tier::net::PeerId&,
                             std::span<const tier::crypto::Byte> p) {
      if (tier::core::peek_control_type(p) ==
          tier::core::ControlType::relay_data) {
        ++relay_forwards_seen;
      }
    });
    tier::net::Endpoint attacker(tier::crypto::NodeIdentity::generate(),
                                 "127.0.0.1", 0);
    const auto t_conn = handshake_with(target_ep, m);
    const auto a_conn = handshake_with(attacker, m);
    check(t_conn != 0 && a_conn != 0, "forward-gate: both peers handshook with m");

    // The attacker hands m a well-formed relay frame addressed to the target
    // (which m is connected to). m is a client, so it must not forward it.
    tier::core::PeerId junk_src{};
    junk_src.fill(0x33);
    const auto sealed = bytes("opaque");
    const auto frame = tier::msg::make_relay_frame(target_id, junk_src, sp(sealed));
    for (int i = 0; i < 400; ++i) {
      attacker.send(a_conn, sp(frame));
      attacker.poll(2);
      m.poll(2);
      target_ep.poll(2);
    }
    check(relay_forwards_seen == 0,
          "forward-gate: a client never forwards a relay frame");
  }

  // --- forgery: a relay frame with a mismatched sender key is dropped ---
  // The relay carries the sender's key as a hint, but authenticity is the inner
  // end-to-end signature. A frame that claims a sender key the sealed message
  // was not signed by must not be delivered; a correctly-keyed one must.
  {
    const auto target_identity = tier::crypto::NodeIdentity::generate();
    tier::net::Node t(target_identity, tier::core::role_bit(Role::client),
                      "127.0.0.1", 0);
    const auto sender = tier::crypto::NodeIdentity::generate();
    const auto impostor = tier::crypto::NodeIdentity::generate();

    tier::net::Endpoint attacker(tier::crypto::NodeIdentity::generate(),
                                 "127.0.0.1", 0);
    const auto conn = handshake_with(attacker, t);
    check(conn != 0, "forgery: attacker handshook with the target");

    // A genuinely sealed device-to-device message (kAppKindNode = 0x00 prefix),
    // signed by `sender` and sealed to the target's keys.
    std::vector<Byte> plaintext{0x00};
    const auto body = bytes("authentic relayed body");
    plaintext.insert(plaintext.end(), body.begin(), body.end());
    const auto sealed = tier::msg::seal(sender, "mainnet", Suite::hybrid,
                                        recipient_of(target_identity), sp(plaintext));

    // Forged frame: same sealed blob, but the claimed sender key is the
    // impostor's. The signature cannot verify under it, so the target drops it.
    const auto forged = tier::msg::make_relay_frame(
        t.peer_id(), impostor.public_key(), sp(sealed));
    for (int i = 0; i < 400; ++i) {
      attacker.send(conn, sp(forged));
      attacker.poll(2);
      t.poll(2);
    }
    check(t.take_inbox().empty(),
          "forgery: a relay frame with a mismatched sender key is dropped");

    // Control: the same sealed blob with the correct sender key is delivered,
    // proving the drop was the key check and not a broken path.
    const auto good = tier::msg::make_relay_frame(
        t.peer_id(), sender.public_key(), sp(sealed));
    bool delivered = false;
    for (int i = 0; i < 400 && !delivered; ++i) {
      attacker.send(conn, sp(good));
      attacker.poll(2);
      t.poll(2);
      for (const auto& msg : t.take_inbox()) {
        if (msg.plaintext == body && msg.sender == id_of(sender)) delivered = true;
      }
    }
    check(delivered,
          "forgery control: a correctly-keyed relay frame is delivered");
  }

  if (g_failures == 0) {
    std::puts("relay: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
