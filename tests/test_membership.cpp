#include <cstdio>

#include "tier/core/membership.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::PeerInfo peer(std::uint8_t tag, std::uint64_t incarnation,
                          tier::core::Liveness liveness) {
  tier::core::PeerInfo info;
  info.id.fill(tag);
  info.addresses = {"127.0.0.1:1"};
  info.incarnation = incarnation;
  info.liveness = liveness;
  return info;
}

// A record with a distinct id derived from `idx` (so many can be minted), given
// roles and liveness. Used for the A3 budget/eviction tests.
tier::core::PeerInfo indexed(unsigned idx, tier::core::RoleSet roles,
                             tier::core::Liveness liveness,
                             std::uint64_t incarnation = 0) {
  tier::core::PeerInfo info;
  info.id[0] = static_cast<std::uint8_t>(idx & 0xFFU);
  info.id[1] = static_cast<std::uint8_t>((idx >> 8) & 0xFFU);
  info.id[2] = static_cast<std::uint8_t>((idx >> 16) & 0xFFU);
  info.roles = roles;
  info.liveness = liveness;
  info.incarnation = incarnation;
  return info;
}

}  // namespace

int main() {
  using tier::core::Liveness;
  using tier::core::Membership;

  Membership m;
  check(m.size() == 0, "starts empty");

  const auto a0 = peer(0xAA, 0, Liveness::alive);
  check(m.apply(a0), "first insert reports a change");
  check(m.size() == 1, "size is 1 after insert");
  check(m.find(a0.id).has_value(), "inserted peer is found");

  // Same incarnation and liveness: no change.
  check(!m.apply(peer(0xAA, 0, Liveness::alive)), "identical update is a no-op");

  // Worse liveness at the same incarnation wins.
  check(m.apply(peer(0xAA, 0, Liveness::suspect)), "suspect supersedes alive");
  check(m.apply(peer(0xAA, 0, Liveness::dead)), "dead supersedes suspect");
  // Better liveness at the same incarnation does not win.
  check(!m.apply(peer(0xAA, 0, Liveness::alive)),
        "alive does not override dead at equal incarnation");

  // Refutation: a higher incarnation wins regardless of liveness.
  check(m.apply(peer(0xAA, 1, Liveness::alive)),
        "higher incarnation refutes dead");
  check(m.find(a0.id)->liveness == Liveness::alive, "refuted peer is alive again");

  // A stale (lower incarnation) update is ignored.
  check(!m.apply(peer(0xAA, 0, Liveness::dead)), "lower incarnation is ignored");

  // A different peer is tracked independently.
  check(m.apply(peer(0xBB, 0, Liveness::alive)), "second peer inserted");
  check(m.size() == 2, "size is 2 with two peers");

  // A liveness-only update (no addresses) must not drop the known dial set.
  {
    tier::core::PeerInfo multi;
    multi.id.fill(0xCC);
    multi.addresses = {"10.0.0.1:7777", "[2001:db8::1]:7777"};
    multi.incarnation = 5;
    multi.liveness = Liveness::alive;
    check(m.apply(multi), "multi-address peer inserted");

    tier::core::PeerInfo liveness_only;
    liveness_only.id.fill(0xCC);
    liveness_only.incarnation = 6;  // higher: supersedes
    liveness_only.liveness = Liveness::suspect;
    check(m.apply(liveness_only), "higher-incarnation liveness update applies");
    const auto cc = m.find(liveness_only.id);
    check(cc && cc->addresses.size() == 2,
          "addresses preserved across a liveness-only update");
    check(cc && cc->liveness == Liveness::suspect, "liveness updated");
  }

  // --- A3: bounded table and eviction policy ---
  {
    using tier::core::Role;
    const tier::core::RoleSet kClient = tier::core::role_bit(Role::client);
    const tier::core::RoleSet kValidator = tier::core::role_bit(Role::validator);

    // Cap of 4. Four alive clients fill it; a fifth distinct alive client is
    // rejected (equal rank, nothing worth evicting), and the table stays bounded.
    Membership b(4);
    for (unsigned i = 0; i < 4; ++i) {
      check(b.apply(indexed(i, kClient, Liveness::alive)),
            "A3: client admitted under the cap");
    }
    check(b.size() == 4, "A3: table filled to the cap");
    check(!b.apply(indexed(100, kClient, Liveness::alive)),
          "A3: a further alive client is rejected when full of alive clients");
    check(b.size() == 4, "A3: size stays at the cap after a rejection");
    check(!b.find(indexed(100, kClient, Liveness::alive).id).has_value(),
          "A3: the rejected client was not stored");

    // An infrastructure record outranks a client and is admitted, evicting one
    // client. The table stays at the cap.
    check(b.apply(indexed(200, kValidator, Liveness::alive)),
          "A3: infrastructure displaces a client when full");
    check(b.size() == 4, "A3: size still at the cap after eviction");
    check(b.find(indexed(200, kValidator, Liveness::alive).id).has_value(),
          "A3: the infrastructure record is kept");
    unsigned clients_left = 0;
    for (unsigned i = 0; i < 4; ++i) {
      if (b.find(indexed(i, kClient, Liveness::alive).id).has_value()) {
        ++clients_left;
      }
    }
    check(clients_left == 3, "A3: exactly one client was evicted");

    // Dead/suspect are evicted before alive. Cap 3: two alive clients and one
    // dead client; a validator evicts the dead client, not an alive one.
    Membership c(3);
    check(c.apply(indexed(1, kClient, Liveness::alive)), "A3: alive client 1");
    check(c.apply(indexed(2, kClient, Liveness::alive)), "A3: alive client 2");
    check(c.apply(indexed(3, kClient, Liveness::dead)), "A3: dead client");
    check(c.apply(indexed(9, kValidator, Liveness::alive)),
          "A3: validator admitted into full table");
    check(!c.find(indexed(3, kClient, Liveness::dead).id).has_value(),
          "A3: the dead client was evicted first");
    check(c.find(indexed(1, kClient, Liveness::alive).id).has_value() &&
              c.find(indexed(2, kClient, Liveness::alive).id).has_value(),
          "A3: both alive clients survived");

    // The pinned (own) id is never evicted, even when it is the least valuable.
    Membership d(2);
    const auto self = indexed(500, kClient, Liveness::alive);
    d.set_pinned(self.id);
    check(d.apply(self), "A3: pinned self inserted");
    check(d.apply(indexed(501, kClient, Liveness::alive)), "A3: a second client");
    check(d.apply(indexed(502, kValidator, Liveness::alive)),
          "A3: validator admitted, evicting the unpinned client");
    check(d.find(self.id).has_value(), "A3: pinned self survived despite low rank");
    check(!d.find(indexed(501, kClient, Liveness::alive).id).has_value(),
          "A3: the unpinned client was the one evicted");

    // A flood of validly-formed junk identities cannot evict a live backbone
    // record, and the table stays bounded.
    Membership e(8);
    const auto backbone = indexed(7000, kValidator, Liveness::alive);
    check(e.apply(backbone), "A3: backbone record inserted");
    for (unsigned i = 0; i < 2000; ++i) {
      e.apply(indexed(10000 + i, kClient, Liveness::alive));  // flood
    }
    check(e.size() == 8, "A3: table stays bounded under a flood");
    check(e.find(backbone.id).has_value(),
          "A3: the live backbone record survived the client flood");

    // An update to an id already present is never subject to the budget.
    Membership f(2);
    check(f.apply(indexed(1, kClient, Liveness::alive, 1)), "A3: first entry");
    check(f.apply(indexed(2, kClient, Liveness::alive, 1)), "A3: table full");
    check(f.apply(indexed(1, kClient, Liveness::alive, 5)),
          "A3: higher-incarnation update to an existing id applies when full");
    check(f.size() == 2, "A3: update did not change the table size");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
