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
  const auto it = peers_.find(update.id);
  if (it == peers_.end()) {
    peers_.emplace(update.id, update);
    return true;
  }

  if (!supersedes(update, it->second)) {
    return false;
  }

  PeerInfo merged = update;
  // Do not drop a known dial address because a liveness-only update omitted it.
  if (merged.address.empty()) {
    merged.address = it->second.address;
  }
  it->second = std::move(merged);
  return true;
}

bool Membership::remove(const PeerId& id) { return peers_.erase(id) > 0; }

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
