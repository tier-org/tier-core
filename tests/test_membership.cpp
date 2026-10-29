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
  info.address = "127.0.0.1:1";
  info.incarnation = incarnation;
  info.liveness = liveness;
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

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
