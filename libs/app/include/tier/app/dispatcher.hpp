#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "tier/app/handler.hpp"
#include "tier/core/membership.hpp"
#include "tier/msg/sealed.hpp"

namespace tier::app {

// A user message as it arrives from the node, before its frame is decoded.
// `frame_bytes` is the opened user-envelope inner plaintext.
struct RawUserMessage {
  tier::core::PeerId sender_user{};
  tier::core::PeerId recipient_user{};
  tier::msg::Suite suite{};
  std::vector<std::uint8_t> frame_bytes;
};

// Routes incoming user messages to per-type handlers. The node enqueues; the
// daemon drains once per poll (sequentially for now - the handler contract makes
// no cross-message ordering promise, so draining can later be split into
// per-type lanes without touching a handler). A message of an unregistered or
// unparseable type is dropped and counted for diagnostics.
class AppDispatcher {
 public:
  // Register the handler for its type(). A second handler for the same type
  // replaces the first.
  void register_handler(std::unique_ptr<AppMessageHandler> handler);

  void enqueue(RawUserMessage msg);

  // Process every queued message through its handler. Messages enqueued during
  // a handler call (e.g. a co-resident receipt delivered via loopback) are
  // processed in the same drain.
  void drain(AppContext& ctx);

  [[nodiscard]] bool empty() const noexcept { return queue_.empty(); }

  // Diagnostics: messages dropped because their type had no handler, keyed by
  // the unknown type id, plus frames that failed to parse at all.
  [[nodiscard]] const std::map<std::uint16_t, std::uint64_t>& unknown_by_type()
      const noexcept {
    return unknown_by_type_;
  }
  [[nodiscard]] std::uint64_t malformed_count() const noexcept {
    return malformed_;
  }

 private:
  std::map<AppType, std::unique_ptr<AppMessageHandler>> handlers_;
  std::deque<RawUserMessage> queue_;
  std::map<std::uint16_t, std::uint64_t> unknown_by_type_;
  std::uint64_t malformed_ = 0;
};

}  // namespace tier::app
