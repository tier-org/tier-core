#include "ui.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ftxui/component/component.hpp"
#include "ftxui/component/component_options.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"
#include "node_client.hpp"
#include "store.hpp"
#include "util.hpp"

namespace tier::messenger {
namespace {

using namespace ftxui;

std::string clock_hhmm(std::int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[6];
  std::snprintf(buf, sizeof(buf), "%02d:%02d", tm.tm_hour, tm.tm_min);
  return buf;
}

// Background reader of one account's event stream. It decodes events off the
// socket and hands them to the UI thread through a locked queue, waking the
// screen after each. All store access stays on the UI thread.
class StreamReader {
 public:
  StreamReader(NodeClient& client, ScreenInteractive& screen) : client_(client), screen_(screen) {}
  ~StreamReader() { stop(); }

  void start(const tier::core::PeerId& account) {
    stop();
    fd_ = client_.open_stream(account);
    connected_ = fd_ >= 0;
    if (fd_ < 0) {
      return;
    }
    stop_ = false;
    thread_ = std::thread([this] { run(); });
  }

  void stop() {
    stop_ = true;
    if (fd_ >= 0) {
      ::shutdown(fd_, SHUT_RDWR);  // unblock a pending recv
    }
    if (thread_.joinable()) {
      thread_.join();
    }
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  [[nodiscard]] bool connected() const noexcept { return connected_; }

  std::vector<tier::core::AdminStreamEvent> drain() {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<tier::core::AdminStreamEvent> out(events_.begin(), events_.end());
    events_.clear();
    return out;
  }

 private:
  void run() {
    StreamParser parser;
    std::array<std::uint8_t, 4096> buf{};
    while (!stop_) {
      const ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
      if (n <= 0) {
        break;  // closed or error
      }
      parser.feed(buf.data(), static_cast<std::size_t>(n));
      bool any = false;
      for (;;) {
        auto ev = parser.next();
        if (!ev.has_value()) {
          break;
        }
        std::lock_guard<std::mutex> lock(mu_);
        events_.push_back(*ev);
        any = true;
      }
      if (any) {
        screen_.PostEvent(Event::Custom);
      }
    }
    connected_ = false;
    screen_.PostEvent(Event::Custom);
  }

  NodeClient& client_;
  ScreenInteractive& screen_;
  std::thread thread_;
  std::atomic<bool> stop_{true};
  std::atomic<bool> connected_{false};
  int fd_ = -1;
  std::mutex mu_;
  std::deque<tier::core::AdminStreamEvent> events_;
};

}  // namespace

int run_ui(NodeClient& client, Store& store, const tier::core::PeerId& account) {
  auto screen = ScreenInteractive::Fullscreen();

  // --- model ------------------------------------------------------------
  std::string account_hex = to_hex(account);
  std::string status = "ready";

  // Chats are the union of contacts and existing conversations, contacts first.
  std::vector<std::string> chat_ids;     // peer user ids (hex)
  std::vector<std::string> chat_labels;  // alias or short id
  int chat_selected = 0;

  auto display_name = [&](const std::string& id) -> std::string {
    const auto a = store.alias_of(id);
    if (a.has_value() && !a->empty()) {
      return *a + " (" + id.substr(0, 8) + ")";
    }
    return id.substr(0, 16);
  };
  auto rebuild_chats = [&] {
    chat_ids.clear();
    chat_labels.clear();
    for (const auto& c : store.contacts()) {
      chat_ids.push_back(c.user_id);
    }
    for (const auto& peer : store.conversations(account_hex)) {
      if (std::find(chat_ids.begin(), chat_ids.end(), peer) == chat_ids.end()) {
        chat_ids.push_back(peer);
      }
    }
    for (const auto& id : chat_ids) {
      chat_labels.push_back(display_name(id));
    }
    if (chat_labels.empty()) {
      chat_labels.push_back("(no chats - add a contact)");
    }
    if (chat_selected >= static_cast<int>(chat_ids.size())) {
      chat_selected = chat_ids.empty() ? 0 : static_cast<int>(chat_ids.size()) - 1;
    }
  };
  rebuild_chats();

  // Suite selector.
  std::vector<std::string> suite_entries = {"classical", "hybrid", "pq"};
  int suite_selected = 1;  // hybrid
  auto suite_value = [&]() -> std::uint8_t {
    return static_cast<std::uint8_t>(suite_selected + 1);
  };

  // Stream reader for the active account.
  StreamReader reader(client, screen);
  reader.start(account);

  // Apply any events the reader queued: store incoming messages and mark
  // receipts delivered. Runs on the UI thread.
  auto apply_events = [&] {
    for (const auto& ev : reader.drain()) {
      if (ev.kind == tier::core::AdminStreamKind::message) {
        ChatMessage m;
        m.account = account_hex;
        m.peer = to_hex(ev.message.sender_user);
        m.direction = Direction::incoming;
        m.msg_id = ev.message.msg_id;
        m.suite = ev.message.suite;
        m.body.assign(ev.message.payload.begin(), ev.message.payload.end());
        m.ts = static_cast<std::int64_t>(std::time(nullptr));
        store.add_message(m);
      } else {
        store.mark_delivered(account_hex, ev.receipt.msg_id);
      }
    }
    rebuild_chats();
  };

  // --- components -------------------------------------------------------
  auto chat_menu = Menu(&chat_labels, &chat_selected);

  std::string new_id;
  std::string new_alias;
  auto in_id = Input(&new_id, "contact user id (64 hex)");
  auto in_alias = Input(&new_alias, "alias (optional)");
  auto add_contact = [&] {
    const auto id = from_hex(new_id);
    if (!id) {
      status = "invalid id: need 64 hex chars";
      return;
    }
    store.upsert_contact(new_id, new_alias);
    status = "added contact " + (new_alias.empty() ? new_id.substr(0, 16) : new_alias);
    new_id.clear();
    new_alias.clear();
    rebuild_chats();
  };
  auto btn_add = Button("add contact", add_contact);

  std::string draft;
  auto send_current = [&] {
    if (chat_ids.empty()) {
      status = "no contact selected";
      return;
    }
    if (draft.empty()) {
      return;
    }
    const auto to = from_hex(chat_ids[static_cast<std::size_t>(chat_selected)]);
    if (!to) {
      status = "selected chat has an invalid id";
      return;
    }
    const auto mid = client.send_text(account, *to, suite_value(), draft);
    if (!mid) {
      status = "send rejected (recipient offline or not hosted?)";
      return;
    }
    ChatMessage m;
    m.account = account_hex;
    m.peer = chat_ids[static_cast<std::size_t>(chat_selected)];
    m.direction = Direction::outgoing;
    m.msg_id = *mid;
    m.suite = suite_value();
    m.body = draft;
    m.ts = static_cast<std::int64_t>(std::time(nullptr));
    store.add_message(m);
    draft.clear();
    status = "sent";
  };
  InputOption send_opt;
  send_opt.on_enter = send_current;
  auto in_draft = Input(&draft, "type a message, Enter to send", send_opt);
  auto btn_send = Button("send", send_current);
  auto suite_box = Radiobox(&suite_entries, &suite_selected);

  // Chat transcript for the selected conversation.
  auto transcript = Renderer([&] {
    Elements lines;
    if (!chat_ids.empty()) {
      const auto& peer = chat_ids[static_cast<std::size_t>(chat_selected)];
      for (const auto& m : store.history(account_hex, peer)) {
        const bool out = m.direction == Direction::outgoing;
        const std::string who = out ? "me" : "<<";
        std::string tick;
        if (out) {
          tick = m.delivered ? "  ok" : "  .";  // delivered check vs pending
        }
        auto line = hbox({
            text(clock_hhmm(m.ts) + " ") | dim,
            text(who + " ") | (out ? color(Color::Green) : color(Color::Cyan)),
            paragraph(m.body) | flex,
            text(tick) | color(Color::GrayDark),
        });
        lines.push_back(line);
      }
    }
    if (lines.empty()) {
      lines.push_back(text("(no messages yet)") | dim);
    }
    return vbox(std::move(lines)) | vscroll_indicator | frame | flex;
  });

  // Layout containers.
  auto left = Container::Vertical({chat_menu});
  auto compose = Container::Horizontal({in_draft, btn_send});
  auto add_row = Container::Horizontal({in_id, in_alias, btn_add});
  auto right = Container::Vertical({transcript, compose, suite_box, add_row});
  auto root = Container::Horizontal({left, right});

  auto layout = Renderer(root, [&] {
    apply_events();  // pull any stream events before drawing
    const auto acct_alias = store.account_alias(account_hex);
    const std::string acct =
        (acct_alias.has_value() && !acct_alias->empty())
            ? *acct_alias + " (" + account_hex.substr(0, 8) + ")"
            : account_hex.substr(0, 16);
    const std::string conn = reader.connected() ? "connected" : "DISCONNECTED";
    auto header = hbox({
        text(" tier-messenger ") | bold | inverted,
        text("  as: " + acct) | color(Color::Yellow),
        filler(),
        text(conn + " ") | (reader.connected() ? color(Color::Green) : color(Color::Red)),
    });
    auto chat_title =
        chat_ids.empty()
            ? std::string("no chat selected")
            : display_name(chat_ids[static_cast<std::size_t>(chat_selected)]);
    auto body = hbox({
        vbox({
            text("Chats") | bold,
            separator(),
            chat_menu->Render() | vscroll_indicator | frame | flex,
        }) | size(WIDTH, EQUAL, 32) | border,
        vbox({
            text("Chat: " + chat_title) | bold,
            separator(),
            transcript->Render() | flex,
            separator(),
            hbox({text("> "), in_draft->Render() | flex, text(" "), btn_send->Render()}),
            hbox({text("suite: "), suite_box->Render()}),
            separator(),
            text("Add contact") | dim,
            hbox({in_id->Render() | flex, text(" "), in_alias->Render() | flex,
                  text(" "), btn_add->Render()}),
        }) | flex | border,
    }) | flex;
    auto footer = hbox({text(" " + status) | dim});
    return vbox({header, body | flex, footer});
  });

  // Quit on Ctrl-Q or Esc; otherwise events flow to the focused component.
  auto with_quit = CatchEvent(layout, [&](const Event& e) {
    if (e == Event::Custom) {
      return false;  // a stream wake-up: let the renderer pull events
    }
    if (e == Event::Escape) {
      reader.stop();
      screen.Exit();
      return true;
    }
    return false;
  });

  screen.Loop(with_quit);
  reader.stop();
  return 0;
}

}  // namespace tier::messenger
