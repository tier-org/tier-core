#include <cstdio>
#include <utility>
#include <vector>

#include "tier/core/control.hpp"
#include "tier/core/membership.hpp"
#include "tier/core/swim.hpp"

namespace {

using tier::core::ControlType;
using tier::core::FailureDetector;
using tier::core::Liveness;
using tier::core::Membership;
using tier::core::PeerId;
using tier::core::PeerInfo;
using tier::core::SwimConfig;
using Clock = FailureDetector::Clock;

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

PeerId mk(std::uint8_t b) {
  PeerId id{};
  id.fill(b);
  return id;
}

PeerInfo alive_peer(PeerId id, std::uint64_t inc = 1) {
  PeerInfo p;
  p.id = id;
  p.incarnation = inc;
  p.liveness = Liveness::alive;
  return p;
}

// Small, test-sized timings. Clock time is injected, so nothing actually sleeps.
SwimConfig fast_config() {
  SwimConfig cfg;
  cfg.probe_period = std::chrono::milliseconds(100);
  cfg.ping_timeout = std::chrono::milliseconds(40);
  cfg.suspicion_timeout = std::chrono::milliseconds(200);
  cfg.dead_cleanup = std::chrono::milliseconds(200);
  cfg.tombstone_ttl = std::chrono::milliseconds(400);
  cfg.indirect_probes = 3;
  return cfg;
}

using Msg = std::pair<PeerId, std::vector<std::uint8_t>>;

// A recording transport plus the detector under test, over a fresh membership.
struct Harness {
  const PeerId self = mk(0x01);
  Membership m;
  std::vector<Msg> outbox;
  FailureDetector fd;
  Clock::time_point t0 = Clock::now();

  Harness()
      : fd(self, m, fast_config(),
           [this](const PeerId& to, const std::vector<std::uint8_t>& msg) {
             outbox.push_back({to, msg});
           }) {
    m.apply(alive_peer(self));
  }

  Clock::time_point at(int ms) const {
    return t0 + std::chrono::milliseconds(ms);
  }
};

bool is_to(const Msg& msg, const PeerId& who, ControlType type) {
  return msg.first == who && tier::core::peek_control_type(msg.second) == type;
}

}  // namespace

int main() {
  // 1. A ping is sent to a neighbor; its ack clears the probe and the peer is
  //    never suspected even after the period elapses.
  {
    Harness h;
    const PeerId p = mk(0x02);
    h.m.apply(alive_peer(p));

    h.fd.tick(h.at(0), {p});
    check(h.outbox.size() == 1 && is_to(h.outbox[0], p, ControlType::ping),
          "direct: a ping is sent to the neighbor");
    const auto ping = tier::core::decode_ping(h.outbox[0].second);
    check(ping.has_value(), "direct: the ping decodes");
    h.outbox.clear();

    if (ping) {
      h.fd.handle(h.at(10), p, tier::core::encode_ack(ping->seq));
    }
    h.fd.tick(h.at(150), {p});  // past probe_period, but it was acked
    const auto info = h.m.find(p);
    check(info && info->liveness == Liveness::alive,
          "direct: an acked peer stays alive");
  }

  // 2. No direct ack within ping_timeout fans out an indirect probe to a relay.
  {
    Harness h;
    const PeerId p = mk(0x02);
    const PeerId r = mk(0x03);
    h.m.apply(alive_peer(p));
    h.m.apply(alive_peer(r));

    h.fd.tick(h.at(0), {p, r});  // probes one of them
    PeerId target{};
    std::uint64_t seq = 0;
    for (const auto& msg : h.outbox) {
      const auto pg = tier::core::decode_ping(msg.second);
      if (pg) {
        target = msg.first;
        seq = pg->seq;
      }
    }
    check(seq != 0, "indirect: an initial ping went out");
    h.outbox.clear();

    // No ack; cross ping_timeout. Expect a ping_req to the other neighbor,
    // naming the unacked target, carrying the same seq.
    h.fd.tick(h.at(50), {p, r});
    bool found = false;
    for (const auto& msg : h.outbox) {
      const auto pr = tier::core::decode_ping_req(msg.second);
      if (pr && msg.first != target) {
        found = pr->target == target && pr->seq == seq;
      }
    }
    check(found, "indirect: a ping_req is relayed naming the unacked target");

    // The relay forwards the target's ack back to us: the probe clears.
    h.fd.handle(h.at(60), /*relay=*/target == p ? r : p,
                tier::core::encode_ack(seq));
    h.fd.tick(h.at(120), {p, r});
    const auto info = h.m.find(target);
    check(info && info->liveness == Liveness::alive,
          "indirect: an indirectly-acked peer stays alive");
  }

  // 3. A silent neighbor goes suspect, then dead, then is removed.
  {
    Harness h;
    const PeerId p = mk(0x02);
    h.m.apply(alive_peer(p));

    h.fd.tick(h.at(0), {p});    // ping p (never answered)
    h.fd.tick(h.at(100), {p});  // period elapsed -> suspect
    const auto s = h.m.find(p);
    check(s && s->liveness == Liveness::suspect, "fail: silent peer -> suspect");

    h.fd.tick(h.at(310), {p});  // suspicion_timeout elapsed -> dead
    const auto d = h.m.find(p);
    check(d && d->liveness == Liveness::dead, "fail: suspect -> dead");

    h.fd.tick(h.at(520), {p});  // dead_cleanup elapsed -> removed
    check(!h.m.find(p).has_value(), "fail: dead -> removed");
  }

  // 4. Seeing itself reported suspect, a node refutes by raising its incarnation.
  {
    Harness h;
    PeerInfo accuse = alive_peer(h.self, 1);
    accuse.liveness = Liveness::suspect;  // same incarnation: supersedes alive
    h.m.apply(accuse);
    check(h.m.find(h.self)->liveness == Liveness::suspect,
          "refute: self starts out accused");

    h.fd.tick(h.at(0), {});
    const auto self = h.m.find(h.self);
    check(self && self->liveness == Liveness::alive && self->incarnation >= 2,
          "refute: self re-asserts alive at a higher incarnation");
  }

  // 5. A higher-incarnation alive report (a peer's own refutation, via gossip)
  //    clears a suspicion we held.
  {
    Harness h;
    const PeerId p = mk(0x02);
    h.m.apply(alive_peer(p, 1));

    h.fd.tick(h.at(0), {p});
    h.fd.tick(h.at(100), {p});  // -> suspect at incarnation 1
    check(h.m.find(p)->liveness == Liveness::suspect, "refute-peer: suspected");

    h.m.apply(alive_peer(p, 2));  // the peer refutes with a higher incarnation
    h.fd.tick(h.at(150), {p});
    const auto info = h.m.find(p);
    check(info && info->liveness == Liveness::alive && info->incarnation == 2,
          "refute-peer: higher-incarnation alive clears the suspicion");
  }

  // 6. A received ping is answered with an ack carrying the same seq.
  {
    Harness h;
    const PeerId x = mk(0x09);
    h.fd.handle(h.at(0), x, tier::core::encode_ping(77));
    check(h.outbox.size() == 1 && is_to(h.outbox[0], x, ControlType::ack),
          "ping: answered with an ack");
    const auto ack = tier::core::decode_ack(h.outbox[0].second);
    check(ack && ack->seq == 77, "ping: the ack echoes the seq");
  }

  // 7. A known peer we hold no connection to (never a neighbor) is still probed
  //    and, staying silent, ages out all the way to removed. This is the fix for
  //    a membership entry that can never be reaped because it is never directly
  //    connected: tick is given an empty neighbor set throughout.
  {
    Harness h;
    const PeerId z = mk(0x07);
    h.m.apply(alive_peer(z));

    h.fd.tick(h.at(0), {});  // no neighbors at all
    bool pinged = false;
    for (const auto& msg : h.outbox) {
      if (is_to(msg, z, ControlType::ping)) {
        pinged = true;
      }
    }
    check(pinged, "zombie: a non-neighbor known peer is still probed");

    h.fd.tick(h.at(100), {});  // period elapsed -> suspect
    const auto s = h.m.find(z);
    check(s && s->liveness == Liveness::suspect, "zombie: non-neighbor -> suspect");

    h.fd.tick(h.at(310), {});  // suspicion_timeout -> dead
    const auto d = h.m.find(z);
    check(d && d->liveness == Liveness::dead, "zombie: suspect -> dead");

    h.fd.tick(h.at(520), {});  // dead_cleanup -> buried (removed)
    check(!h.m.find(z).has_value(), "zombie: dead -> removed");
    check(h.m.is_tombstoned(z), "zombie: removal leaves a tombstone");
  }

  // 8. Stale gossip cannot resurrect a buried peer, but a genuine rejoin at a
  //    strictly higher incarnation can (and lifts the tombstone).
  {
    Harness h;
    const PeerId z = mk(0x08);
    h.m.bury(z, 5);
    check(h.m.is_tombstoned(z), "tombstone: buried");
    check(!h.m.apply(alive_peer(z, 5)),
          "tombstone: same-incarnation gossip rejected");
    check(!h.m.apply(alive_peer(z, 3)), "tombstone: older gossip rejected");
    check(!h.m.find(z).has_value(), "tombstone: not resurrected by stale gossip");
    check(h.m.apply(alive_peer(z, 6)),
          "tombstone: higher-incarnation rejoin accepted");
    const auto info = h.m.find(z);
    check(info && info->liveness == Liveness::alive, "tombstone: rejoined peer present");
    check(!h.m.is_tombstoned(z), "tombstone: lifted on rejoin");
  }

  // 9. A tombstone is lifted after tombstone_ttl, so a long-silent id becomes
  //    learnable again and the detector stops tracking it.
  {
    Harness h;
    const PeerId z = mk(0x0A);
    h.m.apply(alive_peer(z));
    h.fd.tick(h.at(0), {});
    h.fd.tick(h.at(100), {});  // suspect
    h.fd.tick(h.at(310), {});  // dead
    h.fd.tick(h.at(520), {});  // buried (~520)
    check(h.m.is_tombstoned(z), "ttl: tombstoned after burial");

    h.fd.tick(h.at(950), {});  // past tombstone_ttl (400ms) from burial
    check(!h.m.is_tombstoned(z), "ttl: tombstone lifted after tombstone_ttl");
    check(h.m.apply(alive_peer(z, 1)), "ttl: id learnable again after the lift");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
