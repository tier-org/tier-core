#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <vector>

#include "tier/core/membership.hpp"

// Rendezvous hashing (highest random weight) for client-to-client discovery.
//
// Responsibility for a peer id is assigned to communicators deterministically,
// without any broadcast: the k communicators responsible for `target` are the k
// with the highest score(communicator_id, target), where score is a hash of the
// two ids. Both the registrant and the resolver compute the same set from the
// gossiped communicator list, so a lookup lands where the registration was
// stored. Adding or removing one communicator only reassigns the ids that
// hashed to it, so churn is minimal. See docs/communicator.md.
namespace tier::net {

// Default replication: a presence record is stored on this many communicators
// so a single one going away does not lose it.
inline constexpr std::size_t kPresenceReplicas = 2;

// The up-to-k communicators responsible for `target`, most-responsible first.
// `communicators` may contain duplicates or be unsorted; the result is
// deduplicated and ordered by descending score (ties broken by id), size
// min(k, number of distinct communicators). Deterministic for a given input
// set regardless of input order.
[[nodiscard]] std::vector<tier::core::PeerId> responsible_communicators(
    const tier::core::PeerId& target,
    const std::vector<tier::core::PeerId>& communicators, std::size_t k);

// True if `self` is among the k communicators responsible for `target`.
[[nodiscard]] bool is_responsible_for(
    const tier::core::PeerId& self, const tier::core::PeerId& target,
    const std::vector<tier::core::PeerId>& communicators, std::size_t k);

// Address families a node advertises / reaches over.
struct AddrFamily {
  bool v4 = false;
  bool v6 = false;
};

// Choose which responsible communicator to relay a message to `target` through.
//
// A relay only works if the chosen communicator holds a connection to the
// target, and the target enrolls its presence only with the responsible
// communicators it can reach. So a communicator reachable only over an address
// family the target lacks (e.g. a v6-only communicator for a v4-only target)
// would silently drop the frame. Among the `responsible` set, this prefers the
// first communicator we are `connected` to whose advertised families (`family_of`)
// intersect the target's (`target`); if none is family-compatible (or the target
// family is unknown, i.e. both false), it falls back to the first connected one.
// Returns nullopt only when we are connected to none of them.
[[nodiscard]] std::optional<tier::core::PeerId> choose_relay_communicator(
    const std::vector<tier::core::PeerId>& responsible,
    const std::function<bool(const tier::core::PeerId&)>& connected,
    const std::function<AddrFamily(const tier::core::PeerId&)>& family_of,
    AddrFamily target);

}  // namespace tier::net
