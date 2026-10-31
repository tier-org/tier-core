#include "tier/core/membership.hpp"

namespace tier::core {
namespace {

// Is `candidate` a strictly newer report about a peer than `current`?
bool supersedes(const PeerInfo& candidate, const PeerInfo& current) noexcept {
  if (candidate.incarnation != current.incarnation) {
    return candidate.incarnation > current.incarnation;
  }
  return static_cast<std::uint8_t>(candidate.liveness) >
         static_cast<std::uint8_t>(current.liveness);
}

}  // namespace

bool Membership::apply(const PeerInfo& update) {
  const auto tomb = tombstones_.find(update.id);
  if (tomb != tombstones_.end()) {
    if (update.incarnation <= tomb->second) {
      return false;  // suppressed: a stale report about a buried peer
    }
    tombstones_.erase(tomb);  // a strictly newer report lifts the tombstone
  }

  const auto it = peers_.find(update.id);
  if (it == peers_.end()) {
    peers_.emplace(update.id, update);
    return true;
  }

  if (!supersedes(update, it->second)) {
    return false;
  }

  PeerInfo merged = update;
  // Do not drop known dial addresses because a liveness-only update omitted them.
  if (merged.addresses.empty()) {
    merged.addresses = it->second.addresses;
  }
  it->second = std::move(merged);
  return true;
}

bool Membership::remove(const PeerId& id) { return peers_.erase(id) > 0; }

void Membership::bury(const PeerId& id, std::uint64_t incarnation) {
  peers_.erase(id);
  auto [it, inserted] = tombstones_.try_emplace(id, incarnation);
  if (!inserted && incarnation > it->second) {
    it->second = incarnation;  // keep the highest buried incarnation
  }
}

void Membership::forget(const PeerId& id) { tombstones_.erase(id); }

bool Membership::is_tombstoned(const PeerId& id) const {
  return tombstones_.count(id) != 0;
}

std::optional<PeerInfo> Membership::find(const PeerId& id) const {
  const auto it = peers_.find(id);
  if (it == peers_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::size_t Membership::size() const noexcept { return peers_.size(); }

std::vector<PeerInfo> Membership::snapshot() const {
  std::vector<PeerInfo> out;
  out.reserve(peers_.size());
  for (const auto& [id, info] : peers_) {
    out.push_back(info);
  }
  return out;
}

}  // namespace tier::core
