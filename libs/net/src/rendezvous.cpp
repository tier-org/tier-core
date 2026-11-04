#include "tier/net/rendezvous.hpp"

#include <algorithm>
#include <array>

#include "tier/crypto/hash.hpp"
#include "tier/crypto/primitives.hpp"

namespace tier::net {
namespace {

// score(communicator, target) = SHA-256(communicator_id || target_id). A 32-byte
// digest compared lexicographically; the highest wins. Hashing both ids (rather
// than XORing or hashing the target alone) spreads responsibility evenly and
// makes it independent of how the communicator ids happen to cluster.
tier::crypto::Digest256 score(const tier::core::PeerId& communicator,
                              const tier::core::PeerId& target) {
  std::array<tier::crypto::Byte, 64> buf{};
  std::copy(communicator.begin(), communicator.end(), buf.begin());
  std::copy(target.begin(), target.end(), buf.begin() + communicator.size());
  return tier::crypto::sha256(tier::crypto::ByteSpan(buf.data(), buf.size()));
}

}  // namespace

std::vector<tier::core::PeerId> responsible_communicators(
    const tier::core::PeerId& target,
    const std::vector<tier::core::PeerId>& communicators, std::size_t k) {
  if (k == 0 || communicators.empty()) {
    return {};
  }

  // Deduplicate while preserving each distinct id once.
  std::vector<tier::core::PeerId> distinct(communicators);
  std::sort(distinct.begin(), distinct.end());
  distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());

  struct Scored {
    tier::crypto::Digest256 digest;
    tier::core::PeerId id;
  };
  std::vector<Scored> scored;
  scored.reserve(distinct.size());
  for (const auto& c : distinct) {
    scored.push_back({score(c, target), c});
  }

  // Highest score first; a digest tie (astronomically unlikely) breaks by id so
  // the ordering is still total and deterministic.
  const auto better = [](const Scored& a, const Scored& b) {
    if (a.digest != b.digest) return a.digest > b.digest;
    return a.id > b.id;
  };
  const std::size_t take = std::min(k, scored.size());
  const auto mid = scored.begin() +
                   static_cast<std::vector<Scored>::difference_type>(take);
  std::partial_sort(scored.begin(), mid, scored.end(), better);

  std::vector<tier::core::PeerId> out;
  out.reserve(take);
  for (std::size_t i = 0; i < take; ++i) {
    out.push_back(scored[i].id);
  }
  return out;
}

bool is_responsible_for(const tier::core::PeerId& self,
                        const tier::core::PeerId& target,
                        const std::vector<tier::core::PeerId>& communicators,
                        std::size_t k) {
  const auto top = responsible_communicators(target, communicators, k);
  return std::find(top.begin(), top.end(), self) != top.end();
}

}  // namespace tier::net
