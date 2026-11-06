// Tests for the application protocol layer (tier::app): frame codec, the
// dispatcher's routing/diagnostics, and the built-in text + delivery_receipt
// handlers, driven against a fake AppContext (no node, no sockets).
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "tier/app/dispatcher.hpp"
#include "tier/app/frame.hpp"
#include "tier/app/handler.hpp"
#include "tier/core/membership.hpp"
#include "tier/msg/sealed.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::app::AppFrame;
using tier::app::AppType;
using tier::core::PeerId;
using tier::msg::Suite;

PeerId id_of(std::uint8_t tag) {
  PeerId p{};
  p[0] = tag;
  return p;
}

// Records every call so the tests can assert what each handler did.
struct FakeContext : tier::app::AppContext {
  struct Delivered {
    PeerId local_user;
    PeerId sender_user;
    AppType type;
    std::array<std::uint8_t, tier::app::kMsgIdLen> msg_id;
    std::vector<std::uint8_t> payload;
  };
  struct Sent {
    PeerId from_user;
    PeerId to_user;
    AppFrame frame;
  };

  std::vector<Delivered> messages;
  std::vector<std::pair<PeerId, std::array<std::uint8_t, tier::app::kMsgIdLen>>> receipts;
  std::vector<Sent> sent;
  bool subscriber_present = true;  // deliver_message/ deliver_receipt return this

  bool deliver_message(const PeerId& local_user, const PeerId& sender_user,
                       Suite, const AppFrame& frame) override {
    messages.push_back({local_user, sender_user, frame.type, frame.msg_id, frame.payload});
    return subscriber_present;
  }
  bool deliver_receipt(const PeerId& local_user,
                       const std::array<std::uint8_t, tier::app::kMsgIdLen>& id) override {
    receipts.push_back({local_user, id});
    return subscriber_present;
  }
  void send_as(const PeerId& from_user, const PeerId& to_user, Suite,
               const AppFrame& frame) override {
    sent.push_back({from_user, to_user, frame});
  }
};

tier::app::RawUserMessage raw(const PeerId& from, const PeerId& to, const AppFrame& f) {
  return tier::app::RawUserMessage{from, to, Suite::classical, tier::app::encode_app_frame(f)};
}

}  // namespace

int main() {
  const PeerId alice = id_of(0xA1);
  const PeerId bob = id_of(0xB0);

  // --- frame round-trip ---------------------------------------------------
  {
    AppFrame f;
    f.type = AppType::text;
    f.flags = tier::app::kFlagWantsReceipt;
    for (std::size_t i = 0; i < f.msg_id.size(); ++i) f.msg_id[i] = static_cast<std::uint8_t>(i + 1);
    const std::string body = "hello";
    f.payload.assign(body.begin(), body.end());
    const auto bytes = tier::app::encode_app_frame(f);
    const auto back = tier::app::decode_app_frame(bytes);
    check(back.has_value(), "frame decodes");
    check(back && back->type == AppType::text, "frame type preserved");
    check(back && back->wants_receipt(), "frame flags preserved");
    check(back && back->msg_id == f.msg_id, "frame msg_id preserved");
    check(back && back->payload == f.payload, "frame payload preserved");
  }
  // too short, and wrong version
  {
    std::vector<std::uint8_t> tiny(10, 0);
    check(!tier::app::decode_app_frame(tiny).has_value(), "short frame rejected");
    AppFrame f;
    f.type = AppType::text;
    auto bytes = tier::app::encode_app_frame(f);
    bytes[0] = 0xff;  // bogus version
    check(!tier::app::decode_app_frame(bytes).has_value(), "bad version rejected");
  }

  // --- text handler: delivers + emits a receipt when wanted ---------------
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_text_handler());
    d.register_handler(tier::app::make_receipt_handler());

    AppFrame text;
    text.type = AppType::text;
    text.flags = tier::app::kFlagWantsReceipt;
    text.msg_id[0] = 0x42;
    const std::string body = "hi bob";
    text.payload.assign(body.begin(), body.end());

    FakeContext ctx;
    d.enqueue(raw(alice, bob, text));  // alice -> bob, bob is local
    d.drain(ctx);

    check(ctx.messages.size() == 1, "text delivered to subscriber once");
    check(!ctx.messages.empty() && ctx.messages[0].local_user == bob,
          "delivered to the recipient user");
    check(!ctx.messages.empty() && ctx.messages[0].sender_user == alice,
          "delivery carries the sender user");
    check(ctx.sent.size() == 1, "a receipt was emitted");
    check(!ctx.sent.empty() && ctx.sent[0].from_user == bob &&
              ctx.sent[0].to_user == alice,
          "receipt goes from bob back to alice");
    check(!ctx.sent.empty() && ctx.sent[0].frame.type == AppType::delivery_receipt,
          "receipt is a delivery_receipt frame");
    check(!ctx.sent.empty() &&
              ctx.sent[0].frame.payload ==
                  std::vector<std::uint8_t>(text.msg_id.begin(), text.msg_id.end()),
          "receipt payload is the original msg_id");
    check(!ctx.sent.empty() && !ctx.sent[0].frame.wants_receipt(),
          "receipt does not itself request a receipt");
  }

  // --- no live subscriber: dropped, no receipt ----------------------------
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_text_handler());
    AppFrame text;
    text.type = AppType::text;
    text.flags = tier::app::kFlagWantsReceipt;
    FakeContext ctx;
    ctx.subscriber_present = false;
    d.enqueue(raw(alice, bob, text));
    d.drain(ctx);
    check(ctx.messages.size() == 1, "delivery attempted once");
    check(ctx.sent.empty(), "no receipt when no live subscriber");
  }

  // --- text without wants_receipt: delivered, no receipt ------------------
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_text_handler());
    AppFrame text;
    text.type = AppType::text;  // flags = 0
    FakeContext ctx;
    d.enqueue(raw(alice, bob, text));
    d.drain(ctx);
    check(ctx.messages.size() == 1, "delivered");
    check(ctx.sent.empty(), "no receipt requested, none sent");
  }

  // --- receipt handler: notifies the subscriber --------------------------
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_receipt_handler());
    AppFrame r;
    r.type = AppType::delivery_receipt;
    std::array<std::uint8_t, tier::app::kMsgIdLen> acked{};
    acked[0] = 0x99;
    r.payload.assign(acked.begin(), acked.end());
    FakeContext ctx;
    d.enqueue(raw(bob, alice, r));  // bob -> alice (the receipt travels back)
    d.drain(ctx);
    check(ctx.receipts.size() == 1, "receipt delivered to subscriber");
    check(!ctx.receipts.empty() && ctx.receipts[0].first == alice,
          "receipt notified to the recipient user (alice)");
    check(!ctx.receipts.empty() && ctx.receipts[0].second == acked,
          "receipt carries the acked msg_id");
  }
  // malformed receipt payload ignored
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_receipt_handler());
    AppFrame r;
    r.type = AppType::delivery_receipt;
    r.payload = {0x01, 0x02};  // wrong length
    FakeContext ctx;
    d.enqueue(raw(bob, alice, r));
    d.drain(ctx);
    check(ctx.receipts.empty(), "malformed receipt ignored");
  }

  // --- unknown type and malformed frame are counted, not crashed ----------
  {
    tier::app::AppDispatcher d;
    d.register_handler(tier::app::make_text_handler());
    AppFrame unknown;
    unknown.type = static_cast<AppType>(0x7777);
    FakeContext ctx;
    d.enqueue(raw(alice, bob, unknown));
    // a frame too short to decode
    d.enqueue(tier::app::RawUserMessage{alice, bob, Suite::classical, {0x01, 0x02, 0x03}});
    d.drain(ctx);
    check(ctx.messages.empty() && ctx.sent.empty(), "unknown/malformed produced no delivery");
    check(d.unknown_by_type().count(0x7777) == 1 &&
              d.unknown_by_type().at(0x7777) == 1,
          "unknown type counted");
    check(d.malformed_count() == 1, "malformed frame counted");
    check(d.empty(), "queue fully drained");
  }

  if (g_failures == 0) {
    std::puts("test_app OK");
  }
  return g_failures;
}
