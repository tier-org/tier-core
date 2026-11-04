#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "tier/core/membership.hpp"

// A communicator's bounded store of client presence records (see
// docs/communicator.md). Records are opaque, already-verified canonical bytes
// keyed by peer id; the registry does not parse them. It enforces three things:
// a hard entry cap (anti-flood, same spirit as the membership budget), expiry
// so stale registrations age out, and a monotonic incarnation per id so a
// replayed older record cannot roll back a newer one.
namespace tier::net {

inline constexpr std::size_t kDefaultMaxPresenceEntries = 100000;

class PresenceRegistry {
 public:
  PresenceRegistry() = default;
  explicit PresenceRegistry(std::size_t max_entries) : max_entries_(max_entries) {}

  // Store (or refresh) the record for `id`. Rejects a record whose incarnation
  // is not newer than the one already held for that id, and - when the table is
  // full of unexpired entries and `id` is new - rejects rather than evict a
  // live entry. `now_unix` lets a full table make room by dropping expired
  // entries first. Returns true if stored.
  bool store(const tier::core::PeerId& id, std::vector<std::uint8_t> record_bytes,
             std::uint64_t incarnation, std::uint64_t expiry_unix,
             std::uint64_t now_unix);

  // The stored canonical record bytes for `id`, or std::nullopt if absent or
  // expired at `now_unix`.
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> lookup(
      const tier::core::PeerId& id, std::uint64_t now_unix) const;

  // Drop every entry whose expiry is at or before `now_unix`.
  void prune(std::uint64_t now_unix);

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    std::vector<std::uint8_t> bytes;
    std::uint64_t incarnation;
    std::uint64_t expiry_unix;
  };

  std::size_t max_entries_ = kDefaultMaxPresenceEntries;
  std::map<tier::core::PeerId, Entry> entries_;
};

}  // namespace tier::net
