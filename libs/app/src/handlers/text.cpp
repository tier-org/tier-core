#include "tier/app/handler.hpp"

namespace tier::app {
namespace {

// Chat text (0x0001). Deliver to the recipient user's live subscribers; if the
// sender asked for a receipt and at least one subscriber got it, emit a
// delivery_receipt back to the sender user. No live subscriber -> dropped, no
// receipt (online-only, by design).
class TextHandler final : public AppMessageHandler {
 public:
  [[nodiscard]] AppType type() const override { return AppType::text; }

  void handle(const IncomingAppMessage& in, AppContext& ctx) override {
    const bool delivered =
        ctx.deliver_message(in.recipient_user, in.sender_user, in.suite, in.frame);
    if (!delivered || !in.frame.wants_receipt()) {
      return;
    }
    AppFrame receipt;
    receipt.type = AppType::delivery_receipt;
    receipt.flags = 0;  // a receipt is never itself receipted (no loop)
    receipt.payload.assign(in.frame.msg_id.begin(), in.frame.msg_id.end());
    ctx.send_as(in.recipient_user, in.sender_user, in.suite, receipt);
  }
};

}  // namespace

std::unique_ptr<AppMessageHandler> make_text_handler() {
  return std::make_unique<TextHandler>();
}

}  // namespace tier::app
