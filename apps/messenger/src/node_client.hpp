#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "store.hpp"
#include "tier/core/admin.hpp"
#include "tier/core/membership.hpp"

namespace tier::messenger {

// Incremental decoder of the daemon's push stream, which arrives as a sequence
// of length-prefixed records ([u32 BE len][record]). Feed it whatever bytes a
// read returned; pop whole decoded events. Pure and testable (no sockets).
class StreamParser {
 public:
  void feed(const std::uint8_t* data, std::size_t n);
  // The next fully-arrived, well-formed event, or nullopt if none is ready. A
  // record that fails to decode is skipped (not fatal to the stream).
  std::optional<tier::core::AdminStreamEvent> next();

 private:
  std::vector<std::uint8_t> buf_;
};

// Talks to the local tierd over its admin Unix socket: one-shot ops (list/add/
// remove users, send) each open and close their own connection, and open_stream
// opens a long-lived connection subscribed to a user for the push stream.
class NodeClient {
 public:
  explicit NodeClient(std::string path) : path_(std::move(path)) {}

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

  // The local user identities the node hosts, or nullopt if the node is
  // unreachable or replied malformed.
  std::optional<std::vector<tier::core::PeerId>> list_users();
  // Host a new identity (import `seed`, else generate). Returns its user id.
  std::optional<tier::core::PeerId> add_user(
      std::optional<std::array<std::uint8_t, 32>> seed);
  bool remove_user(const tier::core::PeerId& user);

  // Send `body` as a text frame from `from` to `to`, requesting a receipt.
  // Returns the random correlation id on acceptance (to match a later receipt),
  // or nullopt if the node rejected or was unreachable.
  std::optional<MsgId> send_text(const tier::core::PeerId& from,
                                 const tier::core::PeerId& to, std::uint8_t suite,
                                 const std::string& body);

  // Open a blocking connection subscribed to `user`. Returns the socket fd
  // (caller owns and closes it) or -1 on failure. Read records with StreamParser.
  int open_stream(const tier::core::PeerId& user);

 private:
  // Connect, send `req`, half-close, read the whole reply. nullopt on failure.
  std::optional<std::vector<std::uint8_t>> query(
      const std::vector<std::uint8_t>& req);

  std::string path_;
};

}  // namespace tier::messenger
