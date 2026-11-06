#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>

#include "tier/core/membership.hpp"

namespace tier::net {

// Holds the daemon's long-lived subscriber connections (tier-messenger,
// `tierctl stream`), keyed by the local user id each one subscribes to. The
// admin listener hands a subscribed connection's fd here; the daemon publishes
// push events to a user's subscribers as its messages arrive. A user is "live"
// for delivery/receipt purposes exactly while it has at least one subscriber
// that is still writable.
//
// Writes go to blocking fds with a short send timeout (set by the listener), so
// a stuck local client is bounded and then dropped rather than stalling the
// node loop; it never buffers per connection. Not a network surface: the fds
// are accepted Unix-socket connections.
class SubscriberHub {
 public:
  SubscriberHub() = default;
  ~SubscriberHub();
  SubscriberHub(const SubscriberHub&) = delete;
  SubscriberHub& operator=(const SubscriberHub&) = delete;

  // Take ownership of a subscriber connection fd for `user`.
  void add(const tier::core::PeerId& user, int fd);

  // Whether `user` currently has at least one subscriber.
  [[nodiscard]] bool has(const tier::core::PeerId& user) const;

  // Number of subscriber connections across all users.
  [[nodiscard]] std::size_t size() const noexcept { return subs_.size(); }

  // Write one event record to every subscriber of `user`, length-prefixed
  // ([u32 BE len][record]). A connection whose write fails is closed and
  // dropped. Returns how many subscribers received it.
  std::size_t publish(const tier::core::PeerId& user,
                      std::span<const std::uint8_t> record);

  void close_all();

 private:
  std::multimap<tier::core::PeerId, int> subs_;
};

}  // namespace tier::net
