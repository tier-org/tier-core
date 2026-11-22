#include "tier/app/handler.hpp"

namespace tier::app {
namespace {

// Telemetry (0x0003, tier-agent). Deliver to the recipient user's live
// subscribers, exactly like chat text: the node forwards the typed frame to
// whoever is subscribed (a tier-agent collector) and drops it if nobody is
// listening. Metrics are fire-and-forget by design, so - unlike text - no
// delivery receipt is involved. The node still learns nothing about the payload
// semantics; it only routes the frame by type to subscribers.
class TelemetryHandler final : public AppMessageHandler {
 public:
  [[nodiscard]] AppType type() const override { return AppType::telemetry; }

  void handle(const IncomingAppMessage& in, AppContext& ctx) override {
    ctx.deliver_message(in.recipient_user, in.sender_user, in.suite, in.frame);
  }
};

}  // namespace

std::unique_ptr<AppMessageHandler> make_telemetry_handler() {
  return std::make_unique<TelemetryHandler>();
}

}  // namespace tier::app
