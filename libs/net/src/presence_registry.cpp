#include "tier/net/presence_registry.hpp"

#include <utility>

namespace tier::net {

bool PresenceRegistry::store(const tier::core::PeerId& id,
                             std::vector<std::uint8_t> record_bytes,
                             std::uint64_t incarnation, std::uint64_t expiry_unix,
                             std::uint64_t now_unix) {
  // Already expired on arrival: nothing to keep.
  if (expiry_unix <= now_unix) {
    return false;
  }

  const auto it = entries_.find(id);
  if (it != entries_.end()) {
    // Refreshing an existing id: only a strictly newer incarnation wins, so a
    // replayed older signed record cannot roll back the current one.
    if (incarnation <= it->second.incarnation) {
      return false;
    }
    it->second = Entry{std::move(record_bytes), incarnation, expiry_unix};
    return true;
  }

  // A new id. If the table is full, make room only by dropping expired entries;
  // never evict a live registration to admit another.
  if (entries_.size() >= max_entries_) {
    prune(now_unix);
    if (entries_.size() >= max_entries_) {
      return false;
    }
  }
  entries_.emplace(id, Entry{std::move(record_bytes), incarnation, expiry_unix});
  return true;
}

std::optional<std::vector<std::uint8_t>> PresenceRegistry::lookup(
    const tier::core::PeerId& id, std::uint64_t now_unix) const {
  const auto it = entries_.find(id);
  if (it == entries_.end() || it->second.expiry_unix <= now_unix) {
    return std::nullopt;
  }
  return it->second.bytes;
}

void PresenceRegistry::prune(std::uint64_t now_unix) {
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expiry_unix <= now_unix) {
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace tier::net
