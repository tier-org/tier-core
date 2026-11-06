// Tests for the tier-messenger local store (SQLite): contacts + aliases,
// account aliases, message history, and the receipt -> delivered update keyed by
// (account, msg_id). Uses a temporary on-disk database.
#include <unistd.h>

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "node_client.hpp"  // StreamParser
#include "store.hpp"
#include "tier/core/admin.hpp"

namespace {

int g_failures = 0;
void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::messenger::ChatMessage;
using tier::messenger::Direction;
using tier::messenger::MsgId;

MsgId mid(std::uint8_t tag) {
  MsgId m{};
  m[0] = tag;
  return m;
}

}  // namespace

int main() {
  const std::string path = "/tmp/tier-messenger-test-" + std::to_string(::getpid()) + ".db";
  std::remove(path.c_str());

  {
    auto store = tier::messenger::Store::open(path);
    check(store.has_value(), "store opens");
    if (!store) {
      return 1;
    }

    // --- contacts + aliases ---------------------------------------------
    store->upsert_contact("aa", "Alice");
    store->upsert_contact("bb", "");
    store->upsert_contact("aa", "Alice Cooper");  // update alias
    const auto cs = store->contacts();
    check(cs.size() == 2, "two contacts");
    const auto al = store->alias_of("aa");
    check(al && *al == "Alice Cooper", "alias updated");
    check(store->remove_contact("bb"), "remove existing contact");
    check(!store->remove_contact("zz"), "remove missing contact is false");
    check(store->contacts().size() == 1, "one contact left");

    // --- account alias ---------------------------------------------------
    store->set_account_alias("me", "work");
    const auto aa = store->account_alias("me");
    check(aa && *aa == "work", "account alias stored");
    check(!store->account_alias("nope").has_value(), "missing account alias");

    // --- messages + delivery --------------------------------------------
    ChatMessage out;
    out.account = "me";
    out.peer = "aa";
    out.direction = Direction::outgoing;
    out.msg_id = mid(0x42);
    out.suite = 1;
    out.body = "hello alice";
    out.ts = 1000;
    const auto row = store->add_message(out);
    check(row > 0, "outgoing message inserted");

    ChatMessage in;
    in.account = "me";
    in.peer = "aa";
    in.direction = Direction::incoming;
    in.msg_id = mid(0x43);
    in.suite = 1;
    in.body = "hi you";
    in.ts = 1001;
    store->add_message(in);

    auto hist = store->history("me", "aa");
    check(hist.size() == 2, "two messages in history");
    check(hist[0].body == "hello alice" && hist[1].body == "hi you",
          "history ordered oldest first");
    check(!hist[0].delivered, "outgoing starts undelivered");

    const int n = store->mark_delivered("me", mid(0x42));
    check(n == 1, "one outgoing marked delivered");
    check(store->mark_delivered("me", mid(0x99)) == 0, "unknown msg_id marks nothing");
    hist = store->history("me", "aa");
    check(hist[0].delivered, "outgoing now delivered");
    check(!hist[1].delivered || hist[1].direction == Direction::incoming,
          "incoming unaffected by delivered flag");

    // conversations list
    ChatMessage other = in;
    other.peer = "cc";
    other.msg_id = mid(0x44);
    other.ts = 1002;
    store->add_message(other);
    const auto conv = store->conversations("me");
    check(conv.size() == 2, "two conversations for the account");
    check(conv[0] == "cc", "most recent conversation first");
  }

  // Reopen: data persisted.
  {
    auto store = tier::messenger::Store::open(path);
    check(store.has_value(), "store reopens");
    check(store && store->contacts().size() == 1, "contacts persisted across reopen");
    check(store && store->history("me", "aa").size() == 2, "history persisted");
  }
  std::remove(path.c_str());

  // --- StreamParser: frame several length-prefixed records, decode in order ---
  {
    tier::core::AdminStreamMessage m;
    m.suite = 1;
    m.type = 0x0001;
    m.msg_id = mid(0x7);
    const std::string body = "streamed";
    m.payload.assign(body.begin(), body.end());
    tier::core::AdminStreamReceipt r;
    r.msg_id = mid(0x8);

    auto frame = [](const std::vector<std::uint8_t>& rec) {
      std::vector<std::uint8_t> out;
      const auto len = static_cast<std::uint32_t>(rec.size());
      out.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));
      out.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
      out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
      out.push_back(static_cast<std::uint8_t>(len & 0xFF));
      out.insert(out.end(), rec.begin(), rec.end());
      return out;
    };
    const auto rec1 = frame(tier::core::encode_admin_stream_message(m));
    const auto rec2 = frame(tier::core::encode_admin_stream_receipt(r));
    std::vector<std::uint8_t> wire = rec1;
    wire.insert(wire.end(), rec2.begin(), rec2.end());

    tier::messenger::StreamParser p;
    // Feed byte-by-byte to exercise partial-record handling.
    for (const auto b : wire) {
      p.feed(&b, 1);
    }
    const auto e1 = p.next();
    const auto e2 = p.next();
    const auto e3 = p.next();
    check(e1 && e1->kind == tier::core::AdminStreamKind::message, "first event is a message");
    check(e1 && e1->message.payload == m.payload, "message payload parsed");
    check(e2 && e2->kind == tier::core::AdminStreamKind::receipt, "second event is a receipt");
    check(e2 && e2->receipt.msg_id == r.msg_id, "receipt id parsed");
    check(!e3.has_value(), "no third event");
  }

  if (g_failures == 0) {
    std::puts("test_messenger_store OK");
  }
  return g_failures;
}
