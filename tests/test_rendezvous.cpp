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

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
