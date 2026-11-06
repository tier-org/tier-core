#include <algorithm>
#include <array>

#include "tier/app/handler.hpp"

namespace tier::app {
namespace {

// Delivery receipt (0x0002). The payload is the 16-byte msg_id of a message the
// recipient's node delivered to a live subscriber. Notify this user's
// subscribers so a client can mark the message delivered. A payload of the
// wrong length is ignored.
class ReceiptHandler final : public AppMessageHandler {
 public:
  [[nodiscard]] AppType type() const override {
    return AppType::delivery_receipt;
  }

  void handle(const IncomingAppMessage& in, AppContext& ctx) override {
    if (in.frame.payload.size() != kMsgIdLen) {
      return;
    }
    std::array<std::uint8_t, kMsgIdLen> id{};
    std::copy(in.frame.payload.begin(), in.frame.payload.end(), id.begin());
    ctx.deliver_receipt(in.recipient_user, id);
  }
};

}  // namespace

std::unique_ptr<AppMessageHandler> make_receipt_handler() {
  return std::make_unique<ReceiptHandler>();
}

}  // namespace tier::app
