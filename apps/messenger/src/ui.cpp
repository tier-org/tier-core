#include "ui.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
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

enum class Mode : std::uint8_t { Normal, Insert, Command, Prompt, Locked };
enum class Overlay : std::uint8_t { None, Help, Profile, Settings, Book };

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
  auto in_draft = Input(&draft, "", draft_opt);

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
    const std::uint8_t suite = send_suite_for(peer);
    const auto mid = client.send_text(account, *to, suite, draft);
    if (!mid) {
      status = "send rejected (recipient offline or not hosted?)";
      return;
    }
    ChatMessage m;
    m.account = account_hex;
    m.peer = peer;
    m.direction = Direction::outgoing;
    m.msg_id = *mid;
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
            text("  j / k or arrows   move selection"),
            text("  g / G             top / bottom"),
            text("  i or Enter        write a message (INSERT)"),
            text("  :                 command line"),
            text("  ?                 this help"),
            text("  q                 quit"),
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

    Elements tr;
    {
      for (const auto& m : hist) {
        const bool out = m.direction == Direction::outgoing;
        const std::string who = out ? "me" : "<<";
        std::string tick;
        if (out) {
          tick = m.delivered ? " ✓" : " ·";  // check vs middle dot
        }
        tr.push_back(hbox({
            text(clock_hhmm(m.ts) + " ") | dim,
            text(who + " ") | (out ? color(Color::Green) : color(Color::Cyan)),
            paragraph(m.body) | flex,
            text(tick) | color(Color::GrayDark),
        }));
      }
    }
    if (tr.empty()) {
      tr.push_back(text("(no messages yet)") | dim);
    } else {
      tr.back() = tr.back() | focus;  // keep the newest line in view
    }

    // Bottom bar: mode indicator plus whichever line is being edited.
    Element bottom;
    if (mode == Mode::Insert) {
      bottom = hbox({text(" INSERT ") | bold | inverted, text(" "),
                     in_draft->Render() | flex});
    } else if (mode == Mode::Command) {
      bottom = hbox({text(":"), in_cmd->Render() | flex});
    } else if (mode == Mode::Prompt) {
      bottom = hbox({text(prompt_label + " ") | color(Color::Yellow),
                     (prompt_masked ? in_pw->Render() : in_cmd->Render()) |
                         flex});
    } else {
      bottom = hbox({text(" NORMAL ") | bold | inverted,
                     text("  j/k move  i write  : command  ? help  q quit") |
                         dim});
    }

    auto body = hbox({
        vbox({
            text("Chats") | bold,
            separator(),
            vbox(std::move(list)) | vscroll_indicator | yframe | flex,
        }) | size(WIDTH, EQUAL, 28) |
            border,
        vbox({
            hbox({text("Chat: ") | bold, text(chat_title) | bold | flex}),
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
    if (e == Event::ArrowDown || e == Event::Character("j")) {
      if (chat_selected + 1 < static_cast<int>(chat_ids.size())) {
        ++chat_selected;
      }
      return true;
    }
    if (e == Event::ArrowUp || e == Event::Character("k")) {
      if (chat_selected > 0) {
        --chat_selected;
      }
      return true;
    }
    if (e == Event::Character("g")) {
      chat_selected = 0;
      return true;
    }
    if (e == Event::Character("G")) {
      chat_selected = chat_ids.empty() ? 0 : static_cast<int>(chat_ids.size()) - 1;
      return true;
    }
    if (e == Event::Character("i") || e == Event::Character("a") ||
        e == Event::Return) {
      if (selected_id().empty()) {
        status = "no contact - add one with :contacts/add";
      } else {
        draft_cursor = static_cast<int>(draft.size());
        active_tab = 0;
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
    if (e == Event::Character("q")) {
      reader.stop();
      screen.Exit();
      return true;
    }
    return true;  // swallow any other key in NORMAL
  });

  screen.Loop(root);
  reader.stop();
  return 0;
}

}  // namespace tier::messenger
