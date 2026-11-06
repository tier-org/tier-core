#include "tier/app/dispatcher.hpp"

#include <utility>

#include "tier/app/frame.hpp"

namespace tier::app {

void AppDispatcher::register_handler(std::unique_ptr<AppMessageHandler> handler) {
  const AppType t = handler->type();
  handlers_[t] = std::move(handler);
}

void AppDispatcher::enqueue(RawUserMessage msg) {
  queue_.push_back(std::move(msg));
}

void AppDispatcher::drain(AppContext& ctx) {
  // Pop before handling so a message a handler enqueues (a loopback receipt) is
  // appended behind the current one and processed in this same loop.
  while (!queue_.empty()) {
    RawUserMessage msg = std::move(queue_.front());
    queue_.pop_front();

    auto frame = decode_app_frame(
        std::span<const std::uint8_t>(msg.frame_bytes.data(), msg.frame_bytes.size()));
    if (!frame) {
      ++malformed_;
      continue;
    }
    const auto it = handlers_.find(frame->type);
    if (it == handlers_.end()) {
      ++unknown_by_type_[static_cast<std::uint16_t>(frame->type)];
      continue;
    }
    IncomingAppMessage in;
    in.sender_user = msg.sender_user;
    in.recipient_user = msg.recipient_user;
    in.suite = msg.suite;
    in.frame = std::move(*frame);
    it->second->handle(in, ctx);
  }
}

}  // namespace tier::app
