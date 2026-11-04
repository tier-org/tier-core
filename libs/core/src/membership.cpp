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

// Eviction value of an entry: higher is kept longer. Infrastructure (backbone)
// outranks a plain client, and an alive peer outranks a suspect/dead one. The
// least-valuable entry is the one evicted to admit a more valuable new record.
int evict_rank(const PeerInfo& p) noexcept {
  const int base = is_infrastructure(p.roles) ? 2 : 0;
  const int alive = (p.liveness == Liveness::alive) ? 1 : 0;
  return base + alive;
}

}  // namespace

bool Membership::make_room_for(const PeerInfo& incoming) {
  if (peers_.size() < max_entries_) {
    return true;  // room to spare
  }
  // Full: find the least-valuable unpinned entry (ties broken by id order, which
  // is deterministic since peers_ is an ordered map).
  auto victim = peers_.end();
  int victim_rank = 0;
  for (auto it = peers_.begin(); it != peers_.end(); ++it) {
    if (pinned_.has_value() && it->first == *pinned_) {
      continue;  // never evict the node's own record
    }
    const int r = evict_rank(it->second);
    if (victim == peers_.end() || r < victim_rank) {
      victim = it;
      victim_rank = r;
    }
  }
  if (victim == peers_.end()) {
    return false;  // nothing evictable (only the pinned entry)
  }
  if (evict_rank(incoming) <= victim_rank) {
    return false;  // the new record is no more valuable than the least valuable
  }
  peers_.erase(victim);
  return true;
}

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
    // A new id is subject to the table budget (A3): admit it only if there is
    // room, or an eviction of a strictly-less-valuable entry can make room.
    if (!make_room_for(update)) {
      return false;
    }
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
  // Likewise keep a known version when an update carries none (an older peer or
  // a liveness-only report), rather than blanking it.
  if (merged.version.empty()) {
    merged.version = it->second.version;
  }
  // Keep the owner's public key and signature when an update omits them, so a
  // record stays verifiable after a liveness-only merge. A real signed update
  // always carries its own, so this only fills in for an unsigned report.
  if (merged.signature.empty()) {
    merged.public_key = it->second.public_key;
    merged.signature = it->second.signature;
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
