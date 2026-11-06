#pragma once

#include <array>
#include <memory>

#include "tier/app/frame.hpp"
#include "tier/app/registry.hpp"
#include "tier/core/membership.hpp"
#include "tier/msg/sealed.hpp"

namespace tier::app {

// A decoded, routable application message handed to a handler. `recipient_user`
// is a user hosted on this node; `sender_user` is the authenticated sending user.
struct IncomingAppMessage {
  tier::core::PeerId sender_user{};
  tier::core::PeerId recipient_user{};
  tier::msg::Suite suite{};
  AppFrame frame;
};

// The only surface a handler sees - the application SDK. A handler never touches
// sockets, the admin protocol, or libs/net; it works through this. The daemon
// provides the concrete implementation (subscriber delivery + node send).
class AppContext {
 public:
  virtual ~AppContext() = default;

  // Deliver a chat-visible message to every live subscriber of `local_user`.
  // Returns true if at least one subscriber received it (the online-only
  // delivery test: false means no live client, so the message is dropped).
  virtual bool deliver_message(const tier::core::PeerId& local_user,
                               const tier::core::PeerId& sender_user,
                               tier::msg::Suite suite, const AppFrame& frame) = 0;

  // Notify subscribers of `local_user` that `msg_id` was delivered. Returns
  // true if at least one subscriber received the notification.
  virtual bool deliver_receipt(
      const tier::core::PeerId& local_user,
      const std::array<std::uint8_t, kMsgIdLen>& msg_id) = 0;

  // Send an application frame as `from_user` (hosted here) to `to_user`, e.g. a
  // handler emitting a delivery receipt. Fire-and-forget, online-only.
  virtual void send_as(const tier::core::PeerId& from_user,
                       const tier::core::PeerId& to_user, tier::msg::Suite suite,
                       const AppFrame& frame) = 0;
};

// One application message type's logic, fully self-contained. See
// docs/app-protocol.md for how to add one.
class AppMessageHandler {
 public:
  virtual ~AppMessageHandler() = default;
  [[nodiscard]] virtual AppType type() const = 0;
  virtual void handle(const IncomingAppMessage& in, AppContext& ctx) = 0;
};

// Built-in handler factories (one translation unit each).
std::unique_ptr<AppMessageHandler> make_text_handler();
std::unique_ptr<AppMessageHandler> make_receipt_handler();

}  // namespace tier::app
