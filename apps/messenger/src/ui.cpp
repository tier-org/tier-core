#include "ui.hpp"

#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ftxui/component/component.hpp"
#include "ftxui/component/component_options.hpp"
#include "ftxui/component/event.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"
#include "node_client.hpp"
#include "store.hpp"
#include "tier/app/registry.hpp"
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

// A local calendar-day key (YYYYMMDD in local time). Comparing two keys tells
// whether two timestamps fall on different days, across month and year bounds.
std::int64_t local_day_key(std::int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  localtime_r(&t, &tm);
  return (tm.tm_year + 1900) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday;
}

// Human day label with weekday, e.g. "Thu, 12 Nov 2026".
std::string day_label(std::int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%a, %d %b %Y", &tm);
  return buf;
}

const char* suite_name(std::uint8_t s) {
  switch (s) {
    case 1:
      return "classical";
    case 2:
      return "hybrid";
    case 3:
      return "pq";
    default:
      return "?";
  }
}

std::optional<std::uint8_t> parse_suite(const std::string& v) {
  if (v == "classical") return std::uint8_t{1};
  if (v == "hybrid") return std::uint8_t{2};
  if (v == "pq") return std::uint8_t{3};
  return std::nullopt;
}

std::string trim(std::string s) {
  const auto notspace = [](unsigned char c) { return std::isspace(c) == 0; };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
  s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
  return s;
}

// Group a 64-hex id into 8-char blocks, four per line, so two people can read
// it out and compare it character by character.
std::string grouped_id(const std::string& hex) {
  std::string out;
  for (std::size_t i = 0; i < hex.size(); i += 8) {
    out += hex.substr(i, 8);
    const std::size_t group = (i / 8) + 1;
    if (i + 8 < hex.size()) {
      out += (group % 4 == 0) ? '\n' : ' ';
    }
  }
  return out;
}

// Background reader of one account's event stream. It decodes events off the
// socket and hands them to the UI thread through a locked queue, waking the
// screen after each. All store access stays on the UI thread.
class StreamReader {
 public:
  StreamReader(NodeClient& client, ScreenInteractive& screen)
      : client_(client), screen_(screen) {}
  ~StreamReader() { stop(); }

  StreamReader(const StreamReader&) = delete;
  StreamReader& operator=(const StreamReader&) = delete;
  StreamReader(StreamReader&&) = delete;
  StreamReader& operator=(StreamReader&&) = delete;

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

// Background poller of one contact's online status. user_status is a blocking
// admin round-trip, so it never runs on the UI thread; the result is read
// atomically by the renderer. The target follows the selected chat; switching
// target resets to unknown and polls promptly.
class PresencePoller {
 public:
  PresencePoller(NodeClient& client, ScreenInteractive& screen)
      : client_(client), screen_(screen) {}
  ~PresencePoller() { stop(); }
  PresencePoller(const PresencePoller&) = delete;
  PresencePoller& operator=(const PresencePoller&) = delete;

  void start() {
    stop_ = false;
    thread_ = std::thread([this] { run(); });
  }
  void stop() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) {
      thread_.join();
    }
  }
  void set_target(const tier::core::PeerId& user) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (has_target_ && target_ == user) {
        return;
      }
      target_ = user;
      has_target_ = true;
      state_.store(tier::core::UserPresence::unknown);
    }
    cv_.notify_all();
  }
  void clear_target() {
    std::lock_guard<std::mutex> lk(mu_);
    has_target_ = false;
    state_.store(tier::core::UserPresence::unknown);
  }
  [[nodiscard]] tier::core::UserPresence state() const { return state_.load(); }

 private:
  void run() {
    std::unique_lock<std::mutex> lk(mu_);
    while (!stop_) {
      if (has_target_) {
        const tier::core::PeerId target = target_;
        lk.unlock();
        const auto s = client_.user_status(target);
        lk.lock();
        if (has_target_ && target_ == target) {
          state_.store(s);
          screen_.PostEvent(Event::Custom);
        }
      }
      cv_.wait_for(lk, std::chrono::milliseconds(1500));
    }
  }

  NodeClient& client_;
  ScreenInteractive& screen_;
  std::thread thread_;
  bool stop_ = true;
  std::mutex mu_;
  std::condition_variable cv_;
  tier::core::PeerId target_{};
  bool has_target_ = false;
  std::atomic<tier::core::UserPresence> state_{
      tier::core::UserPresence::unknown};
};

enum class Mode : std::uint8_t { Normal, Insert, Command, Prompt, Locked };
enum class Overlay : std::uint8_t { None, Help, Profile, Settings, Book };
// Which panel NORMAL-mode up/down navigates: the chat list or the message
// transcript. Left/right (or h/l) switch between them.
enum class Pane : std::uint8_t { Chats, Messages };

}  // namespace

int run_ui(NodeClient& client, Store& store, const tier::core::PeerId& account) {
  auto screen = ScreenInteractive::Fullscreen();

  // --- model ------------------------------------------------------------
  const std::string account_hex = to_hex(account);
  std::string status = "ready - press ? for help";

  Mode mode = store.has_password() ? Mode::Locked : Mode::Normal;
  Overlay overlay = Overlay::None;

  // The chat list is the union of contacts and existing conversations, contacts
  // first. Rebuilt whenever either changes.
  std::vector<std::string> chat_ids;  // peer user ids (hex)
  int chat_selected = 0;
  // Message-transcript navigation. `pane` is which panel up/down drives;
  // `msg_selected` is the highlighted message index in the active chat's history
  // (0 = oldest), only meaningful while pane == Messages.
  Pane pane = Pane::Chats;
  int msg_selected = 0;

  auto display_name = [&](const std::string& id) -> std::string {
    const auto a = store.alias_of(id);
    if (a.has_value() && !a->empty()) {
      return *a;
    }
    return id.substr(0, 16);
  };
  auto rebuild_chats = [&] {
    chat_ids.clear();
    for (const auto& c : store.contacts()) {
      chat_ids.push_back(c.user_id);
    }
    for (const auto& peer : store.conversations(account_hex)) {
      if (std::find(chat_ids.begin(), chat_ids.end(), peer) == chat_ids.end()) {
        chat_ids.push_back(peer);
      }
    }
    if (chat_selected >= static_cast<int>(chat_ids.size())) {
      chat_selected = chat_ids.empty() ? 0 : static_cast<int>(chat_ids.size()) - 1;
    }
    if (chat_selected < 0) {
      chat_selected = 0;
    }
  };
  rebuild_chats();

  auto selected_id = [&]() -> std::string {
    if (chat_ids.empty() || chat_selected < 0 ||
        chat_selected >= static_cast<int>(chat_ids.size())) {
      return {};
    }
    return chat_ids[static_cast<std::size_t>(chat_selected)];
  };
  // Number of messages in the selected chat (for message-navigation bounds).
  auto history_count = [&]() -> int {
    const std::string peer = selected_id();
    if (peer.empty()) {
      return 0;
    }
    return static_cast<int>(store.history(account_hex, peer).size());
  };
  // Copy text to the terminal clipboard via OSC 52. This reaches the user's
  // LOCAL clipboard even when the messenger runs over SSH (the terminal emulator
  // interprets the sequence), with no external tool like xclip/pbcopy. Works
  // where the terminal supports OSC 52 - most modern ones; tmux/screen need
  // clipboard passthrough enabled. The write runs on the UI thread, between
  // frames, so it does not interleave with FTXUI's own rendering.
  auto copy_to_clipboard = [](const std::string& text) {
    static constexpr char kB64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string enc;
    enc.reserve(((text.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= text.size(); i += 3) {
      const unsigned n = (static_cast<unsigned>(static_cast<unsigned char>(text[i])) << 16) |
                         (static_cast<unsigned>(static_cast<unsigned char>(text[i + 1])) << 8) |
                         static_cast<unsigned>(static_cast<unsigned char>(text[i + 2]));
      enc.push_back(kB64[(n >> 18) & 63U]);
      enc.push_back(kB64[(n >> 12) & 63U]);
      enc.push_back(kB64[(n >> 6) & 63U]);
      enc.push_back(kB64[n & 63U]);
    }
    const std::size_t rem = text.size() - i;
    if (rem == 1) {
      const unsigned n = static_cast<unsigned>(static_cast<unsigned char>(text[i])) << 16;
      enc.push_back(kB64[(n >> 18) & 63U]);
      enc.push_back(kB64[(n >> 12) & 63U]);
      enc.append("==");
    } else if (rem == 2) {
      const unsigned n = (static_cast<unsigned>(static_cast<unsigned char>(text[i])) << 16) |
                         (static_cast<unsigned>(static_cast<unsigned char>(text[i + 1])) << 8);
      enc.push_back(kB64[(n >> 18) & 63U]);
      enc.push_back(kB64[(n >> 12) & 63U]);
      enc.push_back(kB64[(n >> 6) & 63U]);
      enc.push_back('=');
    }
    const std::string seq = "\033]52;c;" + enc + "\a";
    if (::write(STDOUT_FILENO, seq.data(), seq.size()) < 0) {
      // Best-effort: a failed write just means no copy; nothing to recover.
    }
  };
  // The suite we encrypt to a peer with: their override, else the account
  // default.
  auto send_suite_for = [&](const std::string& peer) -> std::uint8_t {
    const auto c = store.contact(peer);
    if (c.has_value() && c->suite.has_value()) {
      return *c->suite;
    }
    return store.default_suite();
  };

  // Stream reader for the active account.
  StreamReader reader(client, screen);
  reader.start(account);

  // Background online/offline poller for the selected contact (updated as the
  // selection changes; see the draw loop).
  PresencePoller poller(client, screen);
  poller.start();

  // Pull queued stream events: store incoming messages (auto-filing the sender
  // as a contact so they can be named) and mark receipts delivered. UI thread.
  auto apply_events = [&] {
    bool changed = false;
    for (const auto& ev : reader.drain()) {
      if (ev.kind == tier::core::AdminStreamKind::message) {
        const std::string peer = to_hex(ev.message.sender_user);
        store.ensure_contact(peer);
        ChatMessage m;
        m.account = account_hex;
        m.peer = peer;
        m.direction = Direction::incoming;
        m.msg_id = ev.message.msg_id;
        m.suite = ev.message.suite;
        m.body.assign(ev.message.payload.begin(), ev.message.payload.end());
        m.ts = static_cast<std::int64_t>(std::time(nullptr));
        store.add_message(m);
        // End-to-end acknowledgment: now that we actually hold the message, send
        // a delivery receipt back to its sender so their checkmark reflects a
        // real client receipt (the node does not ack on anyone's behalf). Only
        // chat text is acked; receipts are never themselves acked (no loop).
        if (ev.message.type ==
            static_cast<std::uint16_t>(tier::app::AppType::text)) {
          client.send_receipt(account, ev.message.sender_user, ev.message.suite,
                              ev.message.msg_id);
        }
        changed = true;
      } else {
        store.mark_delivered(account_hex, ev.receipt.msg_id);
        changed = true;
      }
    }
    if (changed) {
      rebuild_chats();
    }
  };

  // --- editable lines (one is shown at a time; never side by side, so none of
  // them fight over width) ----------------------------------------------
  std::string draft;
  std::string cmdline;
  std::string pwbuf;
  int draft_cursor = 0;
  int cmd_cursor = 0;
  int pw_cursor = 0;
  int active_tab = 0;  // 0 draft, 1 command/prompt, 2 password

  // Stock InputOption::Default() forces the text color to white, which is
  // invisible on a light-background terminal (the reported "pale grey text").
  // Keep the terminal's default foreground so typed text and commands stay
  // readable on any theme; the blinking bar cursor shows the caret, so we also
  // drop the focused-line inversion.
  const auto input_style = [](InputState state) {
    if (state.is_placeholder) {
      state.element |= dim;
    }
    return state.element;
  };

  InputOption draft_opt;
  draft_opt.multiline = false;
  draft_opt.cursor_position = &draft_cursor;
  draft_opt.transform = input_style;
  auto in_draft = Input(&draft, "Type a message, Enter to send", draft_opt);

  InputOption cmd_opt;
  cmd_opt.multiline = false;
  cmd_opt.cursor_position = &cmd_cursor;
  cmd_opt.transform = input_style;
  auto in_cmd = Input(&cmdline, "", cmd_opt);

  InputOption pw_opt;
  pw_opt.multiline = false;
  pw_opt.password = true;
  pw_opt.cursor_position = &pw_cursor;
  pw_opt.transform = input_style;
  auto in_pw = Input(&pwbuf, "", pw_opt);

  auto inputs = Container::Tab({in_draft, in_cmd, in_pw}, &active_tab);

  // --- prompt machinery (interactive multi-field commands) --------------
  std::string prompt_label;
  bool prompt_masked = false;
  std::function<void(std::string)> prompt_cb;

  auto start_prompt = [&](std::string label, bool masked,
                          std::function<void(std::string)> cb) {
    prompt_label = std::move(label);
    prompt_masked = masked;
    prompt_cb = std::move(cb);
    mode = Mode::Prompt;
    cmdline.clear();
    pwbuf.clear();
    cmd_cursor = 0;
    pw_cursor = 0;
    active_tab = masked ? 2 : 1;
  };

  auto send_current = [&] {
    const std::string peer = selected_id();
    if (peer.empty()) {
      status = "no contact selected";
      return;
    }
    if (draft.empty()) {
      return;
    }
    const auto to = from_hex(peer);
    if (!to) {
      status = "selected chat has an invalid id";
      return;
    }
    // Proactive block: if we already know the contact is offline, do not even
    // try - the node would refuse anyway. (unknown/online fall through; the node
    // is the hard gate.)
    if (poller.state() == tier::core::UserPresence::offline) {
      status = "recipient is offline - cannot send";
      return;
    }
    const std::uint8_t suite = send_suite_for(peer);
    const auto res = client.send_text(account, *to, suite, draft);
    if (res.outcome == NodeClient::SendOutcome::offline) {
      // The node refused because the recipient has no online device. Keep the
      // draft so nothing is lost.
      status = "not sent: recipient is offline";
      return;
    }
    if (res.outcome != NodeClient::SendOutcome::accepted) {
      status = "send rejected (is the node reachable?)";
      return;
    }
    ChatMessage m;
    m.account = account_hex;
    m.peer = peer;
    m.direction = Direction::outgoing;
    m.msg_id = res.id;
    m.suite = suite;
    m.body = draft;
    m.ts = static_cast<std::int64_t>(std::time(nullptr));
    store.add_message(m);
    draft.clear();
    draft_cursor = 0;
    status = "sent";
  };

  // --- command dispatch -------------------------------------------------
  auto run_command = [&](const std::string& raw) {
    const std::string line = trim(raw);
    if (line.empty()) {
      return;
    }
    const auto sp = line.find(' ');
    const std::string verb = line.substr(0, sp);
    const std::string arg =
        sp == std::string::npos ? std::string() : trim(line.substr(sp + 1));

    if (verb == "q" || verb == "quit") {
      reader.stop();
      screen.Exit();
      return;
    }
    if (verb == "help") {
      overlay = Overlay::Help;
      return;
    }
    if (verb == "profile") {
      overlay = Overlay::Profile;
      return;
    }
    if (verb == "profile/name") {
      if (!arg.empty()) {
        store.set_account_alias(account_hex, arg);
        status = "profile name set";
      } else {
        start_prompt("your display name:", false, [&](const std::string& v) {
          store.set_account_alias(account_hex, trim(v));
          status = "profile name set";
        });
      }
      return;
    }
    if (verb == "set") {
      if (arg.empty()) {
        overlay = Overlay::Settings;
        return;
      }
      const auto s2 = arg.find(' ');
      const std::string key = arg.substr(0, s2);
      const std::string val =
          s2 == std::string::npos ? std::string() : trim(arg.substr(s2 + 1));
      if (key == "suite") {
        if (const auto su = parse_suite(val)) {
          store.set_default_suite(*su);
          status = "default suite: " + val;
        } else {
          status = "unknown suite (classical|hybrid|pq)";
        }
      } else {
        status = "unknown setting: " + key;
      }
      return;
    }
    if (verb == "contacts" || verb == "book") {
      overlay = Overlay::Book;
      return;
    }
    if (verb == "contacts/add") {
      start_prompt("contact id (64 hex):", false, [&](const std::string& idv) {
        const std::string id = trim(idv);
        if (!from_hex(id)) {
          status = "invalid id: need 64 hex chars";
          return;
        }
        start_prompt("name (optional):", false,
                     [&, id](const std::string& namev) {
                       store.upsert_contact(id, trim(namev));
                       rebuild_chats();
                       status = "contact added";
                     });
      });
      return;
    }
    if (verb == "contacts/rename") {
      const std::string sel = selected_id();
      if (sel.empty()) {
        status = "no contact selected";
        return;
      }
      if (!arg.empty()) {
        store.upsert_contact(sel, arg);
        rebuild_chats();
        status = "renamed";
      } else {
        start_prompt("new name:", false, [&, sel](const std::string& v) {
          store.upsert_contact(sel, trim(v));
          rebuild_chats();
          status = "renamed";
        });
      }
      return;
    }
    if (verb == "contacts/remove") {
      const std::string sel = selected_id();
      if (sel.empty()) {
        status = "no contact selected";
        return;
      }
      start_prompt("remove " + display_name(sel) + "? type yes:", false,
                   [&, sel](const std::string& v) {
                     if (trim(v) == "yes") {
                       store.remove_contact(sel);
                       rebuild_chats();
                       status = "removed";
                     } else {
                       status = "cancelled";
                     }
                   });
      return;
    }
    if (verb == "contacts/verify") {
      const std::string sel = selected_id();
      if (sel.empty()) {
        status = "no contact selected";
        return;
      }
      const auto c = store.contact(sel);
      const bool nv = !(c.has_value() && c->verified);
      store.set_contact_verified(sel, nv);
      status = nv ? "marked verified" : "marked unverified";
      return;
    }
    if (verb == "contacts/suite") {
      const std::string sel = selected_id();
      if (sel.empty()) {
        status = "no contact selected";
        return;
      }
      if (arg.empty()) {
        status = "usage: contacts/suite <classical|hybrid|pq|default>";
      } else if (arg == "default") {
        store.set_contact_suite(sel, std::nullopt);
        status = "contact suite: default";
      } else if (const auto su = parse_suite(arg)) {
        store.set_contact_suite(sel, su);
        status = "contact suite: " + arg;
      } else {
        status = "unknown suite (classical|hybrid|pq|default)";
      }
      return;
    }
    if (verb == "password/set") {
      start_prompt("new password:", true, [&](const std::string& p1) {
        if (p1.empty()) {
          status = "cancelled (empty password)";
          return;
        }
        start_prompt("repeat password:", true, [&, p1](const std::string& p2) {
          if (p1 != p2) {
            status = "passwords differ - not set";
            return;
          }
          store.set_password(p1);
          status = "device lock enabled";
        });
      });
      return;
    }
    if (verb == "password/off") {
      if (!store.has_password()) {
        status = "no lock is set";
        return;
      }
      start_prompt("current password:", true, [&](const std::string& p) {
        if (store.verify_password(p)) {
          store.clear_password();
          status = "device lock disabled";
        } else {
          status = "wrong password";
        }
      });
      return;
    }
    if (verb == "lock") {
      if (!store.has_password()) {
        status = "set a password first (:password/set)";
        return;
      }
      pwbuf.clear();
      pw_cursor = 0;
      active_tab = 2;
      mode = Mode::Locked;
      return;
    }
    status = "unknown command: " + verb + " (:help)";
  };

  // --- rendering --------------------------------------------------------
  auto draw = Renderer(inputs, [&] {
    apply_events();

    // Header.
    const auto acct_alias = store.account_alias(account_hex);
    const std::string acct = (acct_alias.has_value() && !acct_alias->empty())
                                 ? *acct_alias
                                 : "(unnamed)";
    const bool conn = reader.connected();
    auto header = hbox({
        text(" tier-messenger ") | bold | inverted,
        text("  as: " + acct + " " + account_hex.substr(0, 8)) |
            color(Color::Yellow),
        filler(),
        text(store.has_password() ? "lock " : "") | color(Color::GrayDark),
        text((conn ? "connected" : "DISCONNECTED") + std::string(" ")) |
            (conn ? color(Color::Green) : color(Color::Red)),
    });

    // Locked screen replaces the whole body.
    if (mode == Mode::Locked) {
      auto box = vbox({
                     text("LOCKED") | bold | hcenter,
                     text("") ,
                     hbox({text("password: "), in_pw->Render() | flex}),
                     text("") ,
                     text(status) | dim | hcenter,
                 }) |
                 border | size(WIDTH, EQUAL, 50) | size(HEIGHT, EQUAL, 7) |
                 center;
      return vbox({header, box | flex});
    }

    // Overlays (read-only popups) replace the body until dismissed.
    if (overlay != Overlay::None) {
      Elements lines;
      if (overlay == Overlay::Help) {
        lines = {
            text("Help") | bold,
            separator(),
            text("NORMAL mode keys:"),
            text("  h / l or left/right   focus chats / messages pane"),
            text("  j / k or up/down      move within the focused pane"),
            text("  g / G                 top / bottom of the pane"),
            text("  y                     copy selected message (messages pane)"),
            text("  i or Enter        write a message (INSERT)"),
            text("  :                 command line"),
            text("  ?                 this help"),
            text("  :q                quit (no bare q)"),
            text("INSERT: type, Enter sends, Esc back to NORMAL."),
            separator(),
            text("Commands:"),
            text("  :profile                 show your id (share to verify)"),
            text("  :profile/name [name]     set your display name"),
            text("  :contacts                address book"),
            text("  :contacts/add            add a contact (prompts id, name)"),
            text("  :contacts/rename [name]  rename selected contact"),
            text("  :contacts/remove         remove selected contact"),
            text("  :contacts/verify         toggle selected as id-verified"),
            text("  :contacts/suite <s>      per-contact suite (or 'default')"),
            text("  :set                     settings"),
            text("  :set suite <s>           default suite classical|hybrid|pq"),
            text("  :password/set            enable device lock"),
            text("  :password/off            disable device lock"),
            text("  :lock                    lock now"),
            text("  :q                       quit"),
        };
      } else if (overlay == Overlay::Profile) {
        lines = {
            text("Your profile") | bold,
            separator(),
            hbox({text("name: "), text(acct) | color(Color::Yellow)}),
            text(""),
            text("Your id - share it so others can verify they are talking") |
                dim,
            text("to you, and verify theirs the same way:") | dim,
            text(""),
            paragraph(grouped_id(account_hex)) | color(Color::Cyan),
            text(""),
            hbox({text("default suite: "),
                  text(suite_name(store.default_suite()))}),
        };
      } else if (overlay == Overlay::Settings) {
        lines = {
            text("Settings") | bold,
            separator(),
            hbox({text("default suite: "),
                  text(suite_name(store.default_suite())) |
                      color(Color::Yellow)}),
            text("  change: :set suite <classical|hybrid|pq>") | dim,
            text(""),
            hbox({text("device lock: "),
                  text(store.has_password() ? "ON" : "off") |
                      (store.has_password() ? color(Color::Green)
                                            : color(Color::GrayDark))}),
            text("  :password/set  :password/off  :lock") | dim,
        };
      } else {  // Book
        lines.push_back(text("Address book") | bold);
        lines.push_back(separator());
        const auto cs = store.contacts();
        if (cs.empty()) {
          lines.push_back(text("(empty - :contacts/add)") | dim);
        }
        for (const auto& c : cs) {
          const std::string nm = c.alias.empty() ? "(unnamed)" : c.alias;
          const std::string su =
              c.suite.has_value() ? suite_name(*c.suite) : "default";
          lines.push_back(hbox({
              text(c.verified ? "verified " : "- ") |
                  (c.verified ? color(Color::Green) : color(Color::GrayDark)),
              text(nm) | flex,
              text(" " + c.user_id.substr(0, 16)) | dim,
              text("  " + su) | color(Color::Cyan),
          }));
        }
      }
      auto box = vbox(std::move(lines)) | vscroll_indicator | yframe | flex |
                 border | flex;
      return vbox({header, box | flex,
                   hbox({text(" any key / Esc to close ") | dim})});
    }

    // Normal body: chat list on the left, transcript on the right.
    Elements list;
    if (chat_ids.empty()) {
      list.push_back(text("(no chats)") | dim);
      list.push_back(text("add one with :contacts/add") | dim);
    }
    for (std::size_t i = 0; i < chat_ids.size(); ++i) {
      const auto& id = chat_ids[i];
      const auto c = store.contact(id);
      const bool ver = c.has_value() && c->verified;
      const bool sel = static_cast<int>(i) == chat_selected;
      auto row = hbox({
          text(sel ? "> " : "  "),
          text(display_name(id)) | flex,
          text(ver ? " v" : "  ") | color(Color::Green),
      });
      list.push_back(sel ? (row | inverted) : row);
    }

    const std::string peer = selected_id();
    const std::string chat_title = peer.empty() ? "no chat" : display_name(peer);
    const std::vector<ChatMessage> hist =
        peer.empty() ? std::vector<ChatMessage>()
                     : store.history(account_hex, peer);

    // Drive the online/offline poller for the open chat and render a badge.
    tier::core::UserPresence presence = tier::core::UserPresence::unknown;
    if (peer.empty()) {
      poller.clear_target();
    } else if (const auto pid = from_hex(peer)) {
      poller.set_target(*pid);
      presence = poller.state();
    }
    Element presence_badge = text("");
    if (!peer.empty()) {
      switch (presence) {
        case tier::core::UserPresence::online:
          presence_badge = text(" Online ") | color(Color::Green);
          break;
        case tier::core::UserPresence::offline:
          presence_badge = text(" Offline ") | color(Color::Red);
          break;
        case tier::core::UserPresence::unknown:
          presence_badge = text(" ... ") | dim;
          break;
      }
    }

    Element status_sub = text("");
    if (!peer.empty()) {
      const auto c = store.contact(peer);
      const bool ver = c.has_value() && c->verified;
      // What they last sent us under, if anything.
      std::string recv = "-";
      for (auto it = hist.rbegin(); it != hist.rend(); ++it) {
        if (it->direction == Direction::incoming) {
          recv = suite_name(it->suite);
          break;
        }
      }
      status_sub = hbox({
          text("send: ") | dim,
          text(suite_name(send_suite_for(peer))) | color(Color::Cyan),
          text("  recv: ") | dim,
          text(recv) | color(Color::Cyan),
          text("  "),
          text(ver ? "verified" : "UNVERIFIED") |
              (ver ? color(Color::Green) : color(Color::Red)),
      });
    }

    // When the Messages pane is focused, one message is selected (clamped to the
    // live history) and gets highlighted; otherwise nothing is selected and the
    // newest line stays in view.
    const int msg_sel =
        (pane == Pane::Messages && !hist.empty())
            ? std::clamp(msg_selected, 0, static_cast<int>(hist.size()) - 1)
            : -1;
    // An outgoing message with no receipt after this many seconds is shown as
    // failed (✗): with online-only delivery and a client-originated receipt, a
    // missing ack within the window means it did not reach the recipient. A late
    // ack still flips it back to ✓ on the next render.
    constexpr std::int64_t kReceiptTimeoutSecs = 10;
    const std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));

    Elements tr;
    int sel_row = -1;  // index in `tr` of the selected message row, if any
    {
      std::int64_t prev_day = 0;
      bool first = true;
      int idx = 0;
      for (const auto& m : hist) {
        // A day changes: lay down a full-width rule with the weekday and date on
        // its right end, separating this day's messages from the previous one.
        const std::int64_t day = local_day_key(m.ts);
        if (first || day != prev_day) {
          tr.push_back(hbox({
              vbox({separator()}) | flex,  // horizontal rule filling the width
              text(" " + day_label(m.ts)) | dim,
          }));
        }
        first = false;
        prev_day = day;

        const bool out = m.direction == Direction::outgoing;
        const std::string who = out ? "me" : "<<";
        // Outgoing delivery state: ✓ acknowledged by the recipient's client, ✗
        // no ack within the timeout (treated as not delivered), · still pending.
        Element tick_el = text("");
        if (out) {
          if (m.delivered) {
            tick_el = text(" ✓") | color(Color::GrayDark);
          } else if (now_s - m.ts > kReceiptTimeoutSecs) {
            tick_el = text(" ✗") | color(Color::Red);
          } else {
            tick_el = text(" ·") | color(Color::GrayDark);
          }
        }
        Element row = hbox({
            text(clock_hhmm(m.ts) + " ") | dim,
            text(who + " ") | (out ? color(Color::Green) : color(Color::Cyan)),
            paragraph(m.body) | flex,
            tick_el,
        });
        if (idx == msg_sel) {
          row = row | inverted;
          sel_row = static_cast<int>(tr.size());
        }
        tr.push_back(std::move(row));
        ++idx;
      }
    }
    if (tr.empty()) {
      tr.push_back(text("(no messages yet)") | dim);
    } else if (sel_row >= 0) {
      tr[static_cast<std::size_t>(sel_row)] =
          tr[static_cast<std::size_t>(sel_row)] | focus;  // scroll to selection
    } else {
      tr.back() = tr.back() | focus;  // keep the newest line in view
    }

    // Bottom bar: mode indicator plus whichever line is being edited.
    Element bottom;
    if (mode == Mode::Insert) {
      bottom = hbox({text(" INSERT ") | bold | inverted,
                     text(" > ") | color(Color::Green),
                     in_draft->Render() | flex});
    } else if (mode == Mode::Command) {
      bottom = hbox({text(":"), in_cmd->Render() | flex});
    } else if (mode == Mode::Prompt) {
      bottom = hbox({text(prompt_label + " ") | color(Color::Yellow),
                     (prompt_masked ? in_pw->Render() : in_cmd->Render()) |
                         flex});
    } else {
      bottom = hbox({text(" NORMAL ") | bold | inverted,
                     text("  j/k move  h/l pane  i write  : command  ? help  :q quit") |
                         dim});
    }

    auto body = hbox({
        vbox({
            text("Chats") | bold |
                (pane == Pane::Chats ? color(Color::Cyan) : dim),
            separator(),
            vbox(std::move(list)) | vscroll_indicator | yframe | flex,
        }) | size(WIDTH, EQUAL, 28) |
            border,
        vbox({
            hbox({text("Chat: ") | bold, text(chat_title) | bold | flex,
                  presence_badge,
                  pane == Pane::Messages
                      ? text("[j/k]") | color(Color::Cyan)
                      : text("")}),
            status_sub,
            separator(),
            vbox(std::move(tr)) | vscroll_indicator | yframe | flex,
        }) | flex |
            border,
    });

    // A persistent status line below the input bar. It also keeps the active
    // input off the terminal's very last row: ScreenInteractive cannot place
    // the hardware cursor there and would draw it one row too high, over the
    // panel border (the reported "cursor floats above the text").
    auto statusbar = text(" " + status) | dim;
    return vbox({header, body | flex, bottom, statusbar});
  });

  // --- event routing / modal state machine ------------------------------
  auto root = CatchEvent(draw, [&](const Event& e) {
    if (e == Event::Custom) {
      return false;  // stream wake-up: let the renderer pull events
    }
    if (e.is_mouse()) {
      return true;  // the UI is keyboard-only; swallow all mouse input
    }

    // Ctrl+C never quits the messenger. While typing (any input mode) it
    // resets/aborts the current input; in NORMAL it flashes a reminder of how to
    // quit. Handled here, above every mode branch, so the raw 0x03 byte can
    // never leak into an input buffer. (The terminal's INTR character is
    // disabled around the loop so Ctrl+C arrives as this event instead of a
    // SIGINT that FTXUI would exit on.)
    if (e == Event::Special(std::string(1, '\x03'))) {
      switch (mode) {
        case Mode::Insert:
          draft.clear();
          draft_cursor = 0;
          status = "input cleared";
          break;
        case Mode::Command:
          cmdline.clear();
          cmd_cursor = 0;
          mode = Mode::Normal;
          status = "cancelled";
          break;
        case Mode::Prompt:
          prompt_cb = nullptr;
          cmdline.clear();
          pwbuf.clear();
          cmd_cursor = 0;
          pw_cursor = 0;
          mode = Mode::Normal;
          status = "cancelled";
          break;
        case Mode::Locked:
          pwbuf.clear();
          pw_cursor = 0;
          status = "enter password to unlock";
          break;
        case Mode::Normal:
          overlay = Overlay::None;
          status =
              "Ctrl+C does not quit - :q to quit, ? help, i write, : command";
          break;
      }
      return true;
    }

    if (mode == Mode::Locked) {
      if (e == Event::Return) {
        if (store.verify_password(pwbuf)) {
          pwbuf.clear();
          pw_cursor = 0;
          mode = Mode::Normal;
          status = "unlocked";
        } else {
          pwbuf.clear();
          pw_cursor = 0;
          status = "wrong password";
        }
        return true;
      }
      if (e == Event::Escape) {
        return true;  // cannot escape a lock
      }
      return false;  // characters flow to the password input
    }

    // An open overlay is a transient popup: any key dismisses it.
    if (overlay != Overlay::None) {
      overlay = Overlay::None;
      return true;
    }

    if (mode == Mode::Insert) {
      if (e == Event::Escape) {
        mode = Mode::Normal;
        return true;
      }
      if (e == Event::Return) {
        send_current();
        return true;  // stay in INSERT for a quick back-and-forth
      }
      return false;  // characters flow to the draft input
    }

    if (mode == Mode::Command) {
      if (e == Event::Escape) {
        cmdline.clear();
        cmd_cursor = 0;
        mode = Mode::Normal;
        return true;
      }
      if (e == Event::Return) {
        const std::string line = cmdline;
        cmdline.clear();
        cmd_cursor = 0;
        mode = Mode::Normal;
        run_command(line);
        return true;
      }
      return false;  // characters flow to the command input
    }

    if (mode == Mode::Prompt) {
      if (e == Event::Escape) {
        prompt_cb = nullptr;
        mode = Mode::Normal;
        status = "cancelled";
        return true;
      }
      if (e == Event::Return) {
        const std::string ans = prompt_masked ? pwbuf : cmdline;
        auto cb = prompt_cb;  // copy: the callback may arm the next prompt
        prompt_cb = nullptr;
        mode = Mode::Normal;
        cmdline.clear();
        pwbuf.clear();
        cmd_cursor = 0;
        pw_cursor = 0;
        if (cb) {
          cb(ans);
        }
        return true;
      }
      return false;  // characters flow to the active (masked?) input
    }

    // NORMAL mode: single-key navigation and commands. Everything is consumed
    // so no keystroke leaks into an input.
    // Left/right (or h/l) switch which panel is focused; up/down then navigate
    // within it - the chat list, or the messages of the open chat.
    if (e == Event::ArrowLeft || e == Event::Character("h")) {
      pane = Pane::Chats;
      return true;
    }
    if (e == Event::ArrowRight || e == Event::Character("l")) {
      if (!selected_id().empty()) {
        pane = Pane::Messages;
        const int n = history_count();
        msg_selected = n > 0 ? n - 1 : 0;  // enter at the newest message
      }
      return true;
    }
    if (e == Event::ArrowDown || e == Event::Character("j")) {
      if (pane == Pane::Messages) {
        if (msg_selected + 1 < history_count()) {
          ++msg_selected;
        }
      } else if (chat_selected + 1 < static_cast<int>(chat_ids.size())) {
        ++chat_selected;
      }
      return true;
    }
    if (e == Event::ArrowUp || e == Event::Character("k")) {
      if (pane == Pane::Messages) {
        if (msg_selected > 0) {
          --msg_selected;
        }
      } else if (chat_selected > 0) {
        --chat_selected;
      }
      return true;
    }
    if (e == Event::Character("g")) {
      if (pane == Pane::Messages) {
        msg_selected = 0;
      } else {
        chat_selected = 0;
      }
      return true;
    }
    if (e == Event::Character("G")) {
      if (pane == Pane::Messages) {
        const int n = history_count();
        msg_selected = n > 0 ? n - 1 : 0;
      } else {
        chat_selected =
            chat_ids.empty() ? 0 : static_cast<int>(chat_ids.size()) - 1;
      }
      return true;
    }
    // y: copy the selected message to the clipboard (messages pane only).
    if (e == Event::Character("y")) {
      if (pane != Pane::Messages) {
        status = "focus the messages pane (l) to copy";
        return true;
      }
      const std::string peer = selected_id();
      const std::vector<ChatMessage> hist =
          peer.empty() ? std::vector<ChatMessage>()
                       : store.history(account_hex, peer);
      if (hist.empty()) {
        status = "no message to copy";
        return true;
      }
      const int idx =
          std::clamp(msg_selected, 0, static_cast<int>(hist.size()) - 1);
      copy_to_clipboard(hist[static_cast<std::size_t>(idx)].body);
      status = "message copied to clipboard";
      return true;
    }
    if (e == Event::Character("i") || e == Event::Character("a") ||
        e == Event::Return) {
      if (selected_id().empty()) {
        status = "no contact - add one with :contacts/add";
      } else if (poller.state() == tier::core::UserPresence::offline) {
        // Composer blocked while the contact is offline (online-only delivery).
        status = "recipient is offline - cannot send";
      } else {
        draft_cursor = static_cast<int>(draft.size());
        active_tab = 0;
        pane = Pane::Chats;  // writing: keep the newest messages in view
        mode = Mode::Insert;
      }
      return true;
    }
    if (e == Event::Character(":")) {
      cmdline.clear();
      cmd_cursor = 0;
      active_tab = 1;
      mode = Mode::Command;
      return true;
    }
    if (e == Event::Character("?")) {
      overlay = Overlay::Help;
      return true;
    }
    // Quit is deliberately only ':q' (vim-style), never a bare 'q', so a stray
    // keypress cannot drop the user out of the messenger.
    return true;  // swallow any other key in NORMAL
  });

  // Keep Ctrl+C from quitting. FTXUI leaves ISIG enabled, so by default Ctrl+C
  // raises SIGINT and FTXUI exits before any component sees it. Disable only the
  // INTR control character (not all of ISIG, so Ctrl+Z / suspend still works):
  // Ctrl+C then arrives as an ordinary input byte, surfaced as
  // Event::Special("\x03") and handled in the event router above. FTXUI snapshots
  // and restores this termios around its own loop, so we restore the true
  // original once Loop returns.
  struct termios saved_termios {};
  const bool have_termios = tcgetattr(STDIN_FILENO, &saved_termios) == 0;
  if (have_termios) {
    struct termios t = saved_termios;
    t.c_cc[VINTR] = _POSIX_VDISABLE;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
  }

  screen.Loop(root);

  if (have_termios) {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
  }
  reader.stop();
  poller.stop();
  return 0;
}

}  // namespace tier::messenger
