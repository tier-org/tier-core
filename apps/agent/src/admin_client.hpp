#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

#include "tier/core/admin.hpp"
#include "tier/core/membership.hpp"

namespace tier::agent {

// Thin client over tierd's admin UNIX socket - the same interface the messenger
// and tierctl use. tier-agent embeds no network node; it drives a running tierd.
class AdminClient {
 public:
  explicit AdminClient(std::string socket_path)
      : path_(std::move(socket_path)) {}

  // Host (or import) a user identity on the daemon. Returns its user id.
  [[nodiscard]] std::optional<tier::core::PeerId> add_user(
      const std::array<std::uint8_t, 32>& seed);

  // Read identities hosted by the local daemon. Every admin query is bounded.
  [[nodiscard]] std::optional<std::vector<tier::core::PeerId>> local_users();

  // Ship an agent envelope (already encoded) from `from_user` to `to_user` as a
  // telemetry app message. Returns the daemon's send status.
  [[nodiscard]] tier::core::SendStatus send_telemetry(
      const tier::core::PeerId& from_user, const tier::core::PeerId& to_user,
      const std::vector<std::uint8_t>& envelope);

  // Open a subscribed stream for `user`. Returns the raw socket fd (caller reads
  // length-framed events and feeds them to StreamParser), or -1 on failure.
  [[nodiscard]] int open_stream(const tier::core::PeerId& user);

 private:
  std::optional<std::vector<std::uint8_t>> query(
      const std::vector<std::uint8_t>& req);
  std::string path_;
};

// Frames the daemon's push stream: a sequence of [u32 BE len][event-bytes].
class StreamParser {
 public:
  void feed(const std::uint8_t* data, std::size_t n);
  std::optional<tier::core::AdminStreamEvent> next();

 private:
  std::vector<std::uint8_t> buf_;
};

}  // namespace tier::agent
