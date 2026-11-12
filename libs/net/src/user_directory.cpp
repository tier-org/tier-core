#include "tier/net/user_directory.hpp"

namespace tier::net {

bool UserDirectory::enroll(const tier::core::PeerId& user,
                           const tier::core::PeerId& device,
                           std::uint64_t issued_unix, std::uint64_t expiry_unix,
                           std::uint64_t now_unix) {
  if (expiry_unix <= now_unix) {
    return false;  // already expired on arrival
  }

  auto user_it = users_.find(user);
  const bool new_user = user_it == users_.end();

  if (new_user) {
    if (users_.size() >= max_users_) {
      prune(now_unix);
      if (users_.size() >= max_users_) {
        return false;
      }
    }
    user_it = users_.emplace(user, std::map<tier::core::PeerId, Device>{}).first;
  }

  auto& devices = user_it->second;
  const auto dev_it = devices.find(device);
  if (dev_it != devices.end()) {
    // Refresh: only a strictly newer issue stamp wins (anti-rollback).
    if (issued_unix <= dev_it->second.issued_unix) {
      return false;
    }
    dev_it->second = Device{issued_unix, expiry_unix};
    return true;
  }

  // A new device for this user. Reclaim expired slots before refusing.
  if (devices.size() >= max_devices_per_user_) {
    for (auto it = devices.begin(); it != devices.end();) {
      if (it->second.expiry_unix <= now_unix) {
        it = devices.erase(it);
      } else {
        ++it;
      }
    }
    if (devices.size() >= max_devices_per_user_) {
      // Do not leave an empty user behind if we just created one.
      if (new_user && devices.empty()) {
        users_.erase(user_it);
      }
      return false;
    }
  }
  devices.emplace(device, Device{issued_unix, expiry_unix});
  return true;
}

bool UserDirectory::remove(const tier::core::PeerId& user,
                           const tier::core::PeerId& device) {
  const auto user_it = users_.find(user);
  if (user_it == users_.end()) {
    return false;
  }
  const bool erased = user_it->second.erase(device) != 0;
  if (user_it->second.empty()) {
    users_.erase(user_it);
  }
  return erased;
}

std::vector<tier::core::PeerId> UserDirectory::lookup(
    const tier::core::PeerId& user, std::uint64_t now_unix) const {
  std::vector<tier::core::PeerId> out;
  const auto user_it = users_.find(user);
  if (user_it == users_.end()) {
    return out;
  }
  for (const auto& [device, entry] : user_it->second) {
    if (entry.expiry_unix > now_unix) {
      out.push_back(device);  // std::map iterates in sorted key order
    }
  }
  return out;
}

void UserDirectory::prune(std::uint64_t now_unix) {
  for (auto user_it = users_.begin(); user_it != users_.end();) {
    auto& devices = user_it->second;
    for (auto it = devices.begin(); it != devices.end();) {
      if (it->second.expiry_unix <= now_unix) {
        it = devices.erase(it);
      } else {
        ++it;
      }
    }
    if (devices.empty()) {
      user_it = users_.erase(user_it);
    } else {
      ++user_it;
    }
  }
}

}  // namespace tier::net
