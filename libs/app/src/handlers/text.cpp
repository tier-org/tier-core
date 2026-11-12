#include "tier/app/handler.hpp"

namespace tier::app {
namespace {

// Chat text (0x0001). Deliver to the recipient user's live subscribers. No live
// subscriber -> dropped (online-only, by design).
//
// The delivery receipt is deliberately NOT emitted here. A write into a
// subscriber's socket buffer only proves the node queued the bytes, not that the
// recipient's client read them - a client that has gone away (suspended, frozen
// SSH session, a bridged socket) still accepts a buffered write, which would
// produce a checkmark for a message the human never saw. The receipt is instead
// an end-to-end acknowledgment originated by the recipient's own client once it
// actually holds the message (see tier-messenger and `tierctl stream`), so the
// sender's checkmark means "the recipient received it", not "the node buffered
// it".
class TextHandler final : public AppMessageHandler {
 public:
  [[nodiscard]] AppType type() const override { return AppType::text; }

  void handle(const IncomingAppMessage& in, AppContext& ctx) override {
    ctx.deliver_message(in.recipient_user, in.sender_user, in.suite, in.frame);
  }
};

}  // namespace

std::unique_ptr<AppMessageHandler> make_text_handler() {
  return std::make_unique<TextHandler>();
}

}  // namespace tier::app
