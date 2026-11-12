#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "tier/core/membership.hpp"

// A communicator's bounded directory of which device ids are enrolled under a
// user id (see docs/multi-identity.md). It holds only the mapping, not the
// credentials or any message data: the node verifies a device credential before
// calling enroll(), and nothing durable is stored here beyond short-lived,
// expiring device ids. Bounded in both dimensions (users, and devices per user)
// so it cannot grow without limit, same spirit as the membership and presence
// budgets.
namespace tier::net {

inline constexpr std::size_t kDefaultMaxDirectoryUsers = 100000;
inline constexpr std::size_t kMaxDevicesPerUser = 64;

class UserDirectory {
 public:
  UserDirectory() = default;
  UserDirectory(std::size_t max_users, std::size_t max_devices_per_user)
      : max_users_(max_users), max_devices_per_user_(max_devices_per_user) {}

  // Enroll (or refresh) `device` under `user`. A per-(user,device) monotonic
  // issue stamp rejects a replayed older enrollment. When the user's device set
  // is full of live entries, or the table is full of users, a new entry is
  // refused rather than evicting a live one; expired entries are reclaimed
  // first. Returns true if stored.
  bool enroll(const tier::core::PeerId& user, const tier::core::PeerId& device,
              std::uint64_t issued_unix, std::uint64_t expiry_unix,
              std::uint64_t now_unix);

  // Remove a single (user, device) enrollment, e.g. on an authenticated
  // user_deregister (the device went offline). Returns true if an entry was
  // removed. The user is dropped if it is left with no devices.
  bool remove(const tier::core::PeerId& user, const tier::core::PeerId& device);

  // The live device ids enrolled under `user` at `now_unix` (sorted, unique).
  [[nodiscard]] std::vector<tier::core::PeerId> lookup(
      const tier::core::PeerId& user, std::uint64_t now_unix) const;

  // Drop every expired device, and every user left with no devices.
  void prune(std::uint64_t now_unix);

  [[nodiscard]] std::size_t user_count() const noexcept { return users_.size(); }

 private:
  struct Device {
    std::uint64_t issued_unix;
    std::uint64_t expiry_unix;
  };

  std::size_t max_users_ = kDefaultMaxDirectoryUsers;
  std::size_t max_devices_per_user_ = kMaxDevicesPerUser;
  std::map<tier::core::PeerId, std::map<tier::core::PeerId, Device>> users_;
};

}  // namespace tier::net
