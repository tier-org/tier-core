// Tests for rendezvous hashing (tier::net): determinism, independence from
// input order and duplicates, correct result size, agreement with
// is_responsible_for, and the minimal-churn property (adding a communicator
// moves at most one id out of any target's responsible set).
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/net/rendezvous.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

// A distinct id derived from an index, spread across several bytes so the ids
// do not cluster.
tier::core::PeerId id_from(unsigned idx) {
  tier::core::PeerId id{};
  id[0] = static_cast<std::uint8_t>(idx & 0xFF);
  id[1] = static_cast<std::uint8_t>((idx >> 8) & 0xFF);
  id[7] = static_cast<std::uint8_t>((idx * 31U) & 0xFF);
  id[31] = static_cast<std::uint8_t>((idx * 131U) & 0xFF);
  return id;
}

}  // namespace

int main() {
  using tier::net::responsible_communicators;

  std::vector<tier::core::PeerId> comms;
  for (unsigned i = 1; i <= 20; ++i) comms.push_back(id_from(i));
  const tier::core::PeerId target = id_from(1000);
  const std::size_t k = tier::net::kPresenceReplicas;

  const auto base = responsible_communicators(target, comms, k);
  check(base.size() == k, "result size is k when enough communicators exist");

  // Determinism: same input, same output.
  check(responsible_communicators(target, comms, k) == base, "deterministic");

  // Independent of input order.
  {
    auto shuffled = comms;
    std::rotate(shuffled.begin(), shuffled.begin() + 7, shuffled.end());
    std::reverse(shuffled.begin(), shuffled.end());
    check(responsible_communicators(target, shuffled, k) == base,
          "order-independent");
  }

  // Duplicates do not change the result.
  {
    auto dup = comms;
    dup.insert(dup.end(), comms.begin(), comms.end());
    check(responsible_communicators(target, dup, k) == base,
          "duplicates ignored");
  }

  // is_responsible_for agrees with membership in the top-k set.
  {
    for (const auto& c : comms) {
      const bool in = std::find(base.begin(), base.end(), c) != base.end();
      check(tier::net::is_responsible_for(c, target, comms, k) == in,
            "is_responsible_for matches the top-k set");
    }
  }

  // Fewer communicators than k: return all of them.
  {
    std::vector<tier::core::PeerId> few = {id_from(1)};
    const auto r = responsible_communicators(target, few, k);
    check(r.size() == 1 && r[0] == id_from(1),
          "returns all communicators when fewer than k");
    check(responsible_communicators(target, {}, k).empty(),
          "empty input yields empty result");
    check(responsible_communicators(target, comms, 0).empty(),
          "k=0 yields empty result");
  }

  // Minimal churn: adding one communicator moves at most one id out of the
  // responsible set, for every target. This is the property that keeps a
  // lookup finding a registration across membership changes.
  {
    int bad = 0;
    for (unsigned t = 0; t < 200; ++t) {
      const auto tgt = id_from(5000 + t);
      const auto before = responsible_communicators(tgt, comms, k);
      auto plus = comms;
      plus.push_back(id_from(99999));
      const auto after = responsible_communicators(tgt, plus, k);
      // Count ids present before but gone after.
      int removed = 0;
      for (const auto& b : before) {
        if (std::find(after.begin(), after.end(), b) == after.end()) ++removed;
      }
      if (removed > 1) ++bad;
    }
    check(bad == 0, "adding a communicator evicts at most one id per target");
  }

  // --- choose_relay_communicator: cross-family relay selection ---
  // Regression for the v6-only-communicator black hole. Two responsible
  // communicators: comm6 is v6-only, comm46 is dual-stack. We are connected to
  // both. A v4-only target can only be reached through the dual-stack one;
  // picking the v6-only relay would silently drop the message.
  {
    using tier::net::AddrFamily;
    using tier::net::choose_relay_communicator;

    const auto comm6 = id_from(700001);   // v6-only communicator
    const auto comm46 = id_from(700002);  // dual-stack communicator
    const auto connected_both = [&](const tier::core::PeerId&) { return true; };
    const auto fam = [&](const tier::core::PeerId& c) -> AddrFamily {
      if (c == comm6) return {false, true};     // v6 only
      if (c == comm46) return {true, true};      // v4 + v6
      return {};
    };
    const AddrFamily v4_target{true, false};
    const AddrFamily v6_target{false, true};
    const AddrFamily unknown_target{false, false};

    // v6-only communicator first in the responsible order, but the target is
    // v4-only: must skip it and pick the dual-stack one.
    check(choose_relay_communicator({comm6, comm46}, connected_both, fam,
                                    v4_target) == comm46,
          "v4 target skips v6-only relay for the dual-stack one");
    // Order must not matter.
    check(choose_relay_communicator({comm46, comm6}, connected_both, fam,
                                    v4_target) == comm46,
          "v4 target picks dual-stack regardless of order");
    // A v6 target is reachable through either; the first connected wins.
    check(choose_relay_communicator({comm6, comm46}, connected_both, fam,
                                    v6_target) == comm6,
          "v6 target accepts the first (v6-capable) relay");
    // Unknown target family: degrade to first connected.
    check(choose_relay_communicator({comm6, comm46}, connected_both, fam,
                                    unknown_target) == comm6,
          "unknown target family falls back to first connected");
    // Only the v6-only relay is connected and the target is v4-only: no family
    // match, but still relay through it as best effort (better than dropping).
    const auto only6_connected = [&](const tier::core::PeerId& c) {
      return c == comm6;
    };
    check(choose_relay_communicator({comm6, comm46}, only6_connected, fam,
                                    v4_target) == comm6,
          "best-effort fallback to the sole connected relay");
    // Connected to none: nothing to relay through.
    const auto none_connected = [&](const tier::core::PeerId&) { return false; };
    check(!choose_relay_communicator({comm6, comm46}, none_connected, fam,
                                     v4_target),
          "no connected relay yields no choice");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
