// tierctl: local admin/diagnostics CLI. Talks to a running tierd over its Unix
// admin socket (one request, one response) and renders the result. Read-only
// for now: `tierctl peers` lists the node's view of the mesh.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "tier/app/frame.hpp"
#include "tier/core/admin.hpp"
#include "tier/core/membership.hpp"

namespace {

const char* kDefaultSocket = "/run/tierd/tierd.sock";

std::string resolve_socket(const char* override_path) {
  if (override_path != nullptr) {
    return override_path;
  }
  if (const char* const env = std::getenv("TIER_ADMIN_SOCK"); env != nullptr) {
    return env;
  }
  return kDefaultSocket;
}

// Connect, send the request, read the whole reply to EOF. Returns false (and
// prints why) if the daemon is not reachable.
bool query_bytes(const std::string& path, const std::vector<std::uint8_t>& req,
                 std::vector<std::uint8_t>& out) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    std::perror("socket");
    return false;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    std::fprintf(stderr, "socket path too long: %s\n", path.c_str());
    ::close(fd);
    return false;
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "cannot connect to tierd at %s: %s\n", path.c_str(),
                 std::strerror(errno));
    std::fprintf(stderr, "is tierd running? (override with TIER_ADMIN_SOCK or --sock)\n");
    ::close(fd);
    return false;
  }

  if (::send(fd, req.data(), req.size(), 0) != static_cast<ssize_t>(req.size())) {
    std::perror("send");
    ::close(fd);
    return false;
  }
  ::shutdown(fd, SHUT_WR);  // signal end-of-request so the daemon can reply

  std::array<std::uint8_t, 4096> buf{};
  for (;;) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) {
      std::perror("recv");
      ::close(fd);
      return false;
    }
    if (n == 0) {
      break;  // daemon closed: full reply received
    }
    out.insert(out.end(), buf.data(), buf.data() + n);
  }
  ::close(fd);
  return true;
}

// Convenience for the no-argument ops (peers, inbox).
bool query(const std::string& path, tier::core::AdminOp op,
           std::vector<std::uint8_t>& out) {
  return query_bytes(path, tier::core::encode_admin_request(op), out);
}

std::string short_id(const tier::core::PeerId& id) {
  static const char* const hex = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < 8 && i < id.size(); ++i) {  // first 8 bytes
    out += hex[id[i] >> 4];
    out += hex[id[i] & 0x0F];
  }
  return out;
}

std::string full_id(const tier::core::PeerId& id) {
  static const char* const hex = "0123456789abcdef";
  std::string out;
  for (const auto b : id) {
    out += hex[b >> 4];
    out += hex[b & 0x0F];
  }
  return out;
}

std::string roles_string(tier::core::RoleSet roles) {
  using tier::core::Role;
  struct Named { Role r; const char* name; };
  static const Named kAll[] = {{Role::client, "client"},
                               {Role::validator, "validator"},
                               {Role::keeper, "keeper"},
                               {Role::transmitter, "transmitter"},
                               {Role::communicator, "communicator"}};
  std::string out;
  for (const Named& n : kAll) {
    if (tier::core::has_role(roles, n.r)) {
      if (!out.empty()) {
        out += '|';
      }
      out += n.name;
    }
  }
  return out.empty() ? "-" : out;
}

const char* liveness_string(tier::core::Liveness l) {
  switch (l) {
    case tier::core::Liveness::alive:
      return "alive";
    case tier::core::Liveness::suspect:
      return "suspect";
    case tier::core::Liveness::dead:
      return "dead";
  }
  return "?";
}

std::string join_addresses(const std::vector<std::string>& addrs) {
  std::string out;
  for (const std::string& a : addrs) {
    if (!out.empty()) {
      out += ',';
    }
    out += a;
  }
  return out.empty() ? "-" : out;
}

int cmd_id(const std::string& path) {
  std::vector<std::uint8_t> reply;
  if (!query(path, tier::core::AdminOp::id, reply)) {
    return 1;
  }
  const auto id = tier::core::decode_admin_id_reply(reply);
  if (!id) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  // The full 64-hex device id (what `tierctl send <peer-id>` expects). User
  // identities hosted on this node are listed separately by `tierctl user ls`.
  std::printf("device %s\n", full_id(id->device_id).c_str());
  return 0;
}

int cmd_peers(const std::string& path) {
  std::vector<std::uint8_t> reply;
  if (!query(path, tier::core::AdminOp::peers, reply)) {
    return 1;
  }
  const auto reply_decoded = tier::core::decode_admin_peers(reply);
  if (!reply_decoded) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  const auto& peers = reply_decoded->peers;

  std::size_t connected = 0;
  for (const auto& p : peers) {
    if (p.connected) {
      ++connected;
    }
  }
  std::printf("network=%s  known=%zu connected=%zu\n\n",
              reply_decoded->network.empty() ? "-"
                                             : reply_decoded->network.c_str(),
              peers.size(), connected);
  std::printf("%-16s  %-4s  %-8s  %-22s  %-10s  %s\n", "PEER", "CONN",
              "LIVENESS", "ROLES", "VERSION", "ADDRESSES");
  for (const auto& p : peers) {
    std::printf("%-16s  %-4s  %-8s  %-22s  %-10s  %s\n",
                short_id(p.info.id).c_str(), p.connected ? "yes" : "no",
                liveness_string(p.info.liveness),
                roles_string(p.info.roles).c_str(),
                p.info.version.empty() ? "-" : p.info.version.c_str(),
                join_addresses(p.info.addresses).c_str());
  }
  return 0;
}

// Parse exactly 64 hex characters into a 32-byte peer id.
std::optional<tier::core::PeerId> parse_peer_id(std::string_view s) {
  if (s.size() != tier::core::PeerId{}.size() * 2) {
    return std::nullopt;
  }
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  tier::core::PeerId id{};
  for (std::size_t i = 0; i < id.size(); ++i) {
    const int hi = nib(s[2 * i]);
    const int lo = nib(s[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    id[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return id;
}

std::optional<std::uint8_t> parse_suite(std::string_view name) {
  if (name == "classical") return static_cast<std::uint8_t>(1);
  if (name == "hybrid") return static_cast<std::uint8_t>(2);
  if (name == "pq") return static_cast<std::uint8_t>(3);
  return std::nullopt;
}

const char* suite_name(std::uint8_t s) {
  switch (s) {
    case 1: return "classical";
    case 2: return "hybrid";
    case 3: return "pq";
    default: return "?";
  }
}

int cmd_send(const std::string& path, std::string_view peer_hex,
             std::string_view suite_name_arg, std::string_view message) {
  const auto id = parse_peer_id(peer_hex);
  if (!id) {
    std::fprintf(stderr, "invalid peer id (expected 64 hex chars)\n");
    return 2;
  }
  const auto suite = parse_suite(suite_name_arg);
  if (!suite) {
    std::fprintf(stderr, "invalid suite (expected classical|hybrid|pq)\n");
    return 2;
  }
  const std::vector<std::uint8_t> pt(message.begin(), message.end());
  if (pt.size() > tier::core::kMaxAdminMessageBytes) {
    std::fprintf(stderr, "message too large (max %zu bytes)\n",
                 tier::core::kMaxAdminMessageBytes);
    return 2;
  }
  const auto req = tier::core::encode_admin_send(
      *id, *suite, std::span<const std::uint8_t>(pt.data(), pt.size()));
  std::vector<std::uint8_t> reply;
  if (!query_bytes(path, req, reply)) {
    return 1;
  }
  const auto ok = tier::core::decode_admin_send_reply(reply);
  if (!ok) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  if (!*ok) {
    std::fprintf(stderr,
                 "not accepted: unknown suite, or no way to reach the peer\n");
    return 1;
  }
  // Accepted for delivery: sent now if already connected, otherwise queued while
  // the node resolves the peer through a communicator and connects to it.
  std::printf("accepted (%s) for %s\n", suite_name(*suite), short_id(*id).c_str());
  return 0;
}

int cmd_send_as(const std::string& path, std::string_view from_hex,
                std::string_view to_hex, std::string_view suite_name_arg,
                std::string_view message) {
  const auto from = parse_peer_id(from_hex);
  const auto to = parse_peer_id(to_hex);
  if (!from || !to) {
    std::fprintf(stderr, "invalid user id (expected 64 hex chars)\n");
    return 2;
  }
  const auto suite = parse_suite(suite_name_arg);
  if (!suite) {
    std::fprintf(stderr, "invalid suite (expected classical|hybrid|pq)\n");
    return 2;
  }
  // Wrap the text in a layer-2 application frame (type text, wanting a delivery
  // receipt, with a random correlation id). The recipient node routes it to the
  // recipient user's live subscriber and, on delivery, returns a receipt. See
  // docs/app-protocol.md.
  tier::app::AppFrame frame;
  frame.type = tier::app::AppType::text;
  frame.flags = tier::app::kFlagWantsReceipt;
  {
    std::random_device rd;
    for (auto& b : frame.msg_id) {
      b = static_cast<std::uint8_t>(rd());
    }
  }
  frame.payload.assign(message.begin(), message.end());
  const auto framed = tier::app::encode_app_frame(frame);
  if (framed.size() > tier::core::kMaxAdminMessageBytes) {
    std::fprintf(stderr, "message too large (max %zu bytes)\n",
                 tier::core::kMaxAdminMessageBytes - 20);
    return 2;
  }
  const auto req = tier::core::encode_admin_send_as(
      *from, *to, *suite,
      std::span<const std::uint8_t>(framed.data(), framed.size()));
  std::vector<std::uint8_t> reply;
  if (!query_bytes(path, req, reply)) {
    return 1;
  }
  const auto status = tier::core::decode_admin_send_as_reply(reply);
  if (!status) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  if (*status == tier::core::SendStatus::recipient_offline) {
    std::fprintf(stderr,
                 "not sent: the recipient user is offline (no online device)\n");
    return 1;
  }
  if (*status != tier::core::SendStatus::accepted) {
    std::fprintf(stderr,
                 "not accepted: unknown suite, or the from-user is not hosted "
                 "on this node\n");
    return 1;
  }
  // Fans out to the recipient user's online devices once resolved through a
  // communicator (a recipient on this same node is delivered locally).
  std::printf("accepted (%s) from user %s to user %s\n", suite_name(*suite),
              short_id(*from).c_str(), short_id(*to).c_str());
  return 0;
}

int cmd_user_add(const std::string& path,
                 std::optional<std::string_view> seed_hex) {
  std::optional<std::array<std::uint8_t, 32>> seed;
  if (seed_hex) {
    const auto parsed = parse_peer_id(*seed_hex);
    if (!parsed) {
      std::fprintf(stderr, "invalid seed (expected 64 hex chars)\n");
      return 2;
    }
    std::array<std::uint8_t, 32> s{};
    std::copy(parsed->begin(), parsed->end(), s.begin());
    seed = s;
  }
  std::vector<std::uint8_t> reply;
  if (!query_bytes(path, tier::core::encode_admin_user_add(seed), reply)) {
    return 1;
  }
  const auto rep = tier::core::decode_admin_user_add_reply(reply);
  if (!rep) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  if (!rep->ok) {
    std::fprintf(stderr, "could not add user (could not persist the seed)\n");
    return 1;
  }
  std::printf("user %s\n", full_id(rep->user_id).c_str());
  return 0;
}

int cmd_user_list(const std::string& path) {
  std::vector<std::uint8_t> reply;
  if (!query(path, tier::core::AdminOp::user_list, reply)) {
    return 1;
  }
  const auto users = tier::core::decode_admin_user_list(reply);
  if (!users) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  std::printf("%zu user(s)\n", users->size());
  for (const auto& u : *users) {
    std::printf("%s\n", full_id(u).c_str());
  }
  return 0;
}

int cmd_user_remove(const std::string& path, std::string_view user_hex) {
  const auto id = parse_peer_id(user_hex);
  if (!id) {
    std::fprintf(stderr, "invalid user id (expected 64 hex chars)\n");
    return 2;
  }
  std::vector<std::uint8_t> reply;
  if (!query_bytes(path, tier::core::encode_admin_user_remove(*id), reply)) {
    return 1;
  }
  const auto existed = tier::core::decode_admin_user_remove_reply(reply);
  if (!existed) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  std::printf("%s %s\n", *existed ? "removed" : "no such user",
              full_id(*id).c_str());
  return *existed ? 0 : 1;
}

int cmd_inbox(const std::string& path) {
  std::vector<std::uint8_t> reply;
  if (!query(path, tier::core::AdminOp::inbox, reply)) {
    return 1;
  }
  const auto messages = tier::core::decode_admin_inbox(reply);
  if (!messages) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  std::printf("%zu message(s)\n", messages->size());
  for (const auto& m : *messages) {
    std::string text(m.plaintext.begin(), m.plaintext.end());
    const std::string user =
        m.sender_user ? ("user " + short_id(*m.sender_user)) : std::string("-");
    // For a user message, also show which local user it was addressed to.
    const std::string to =
        m.recipient_user ? ("  to-user " + short_id(*m.recipient_user))
                         : std::string();
    std::printf("from %s (%s)%s  suite=%s  %zu bytes: %s\n",
                short_id(m.sender).c_str(), user.c_str(), to.c_str(),
                suite_name(m.suite), m.plaintext.size(), text.c_str());
  }
  return 0;
}

std::string short_hex(const std::array<std::uint8_t, 16>& id) {
  static const char* const hex = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < 8; ++i) {  // first 8 bytes
    out += hex[id[i] >> 4];
    out += hex[id[i] & 0x0F];
  }
  return out;
}

// Subscribe as a local user and print the push event stream (chat messages and
// delivery receipts) until the daemon closes or this process is stopped. This
// is the observation path for user messages (they are not buffered in the
// inbox); tier-messenger uses the same protocol. See docs/app-protocol.md.
int cmd_status(const std::string& path, std::string_view user_hex) {
  const auto user = parse_peer_id(user_hex);
  if (!user) {
    std::fprintf(stderr, "invalid user id (expected 64 hex chars)\n");
    return 2;
  }
  std::vector<std::uint8_t> reply;
  if (!query_bytes(path, tier::core::encode_admin_user_status(*user), reply)) {
    return 1;
  }
  const auto state = tier::core::decode_admin_user_status_reply(reply);
  if (!state) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }
  const char* s = "unknown";
  if (*state == tier::core::UserPresence::online) {
    s = "online";
  } else if (*state == tier::core::UserPresence::offline) {
    s = "offline";
  }
  std::printf("%s %s\n", short_id(*user).c_str(), s);
  return 0;
}

int cmd_stream(const std::string& path, std::string_view user_hex) {
  const auto user = parse_peer_id(user_hex);
  if (!user) {
    std::fprintf(stderr, "invalid user id (expected 64 hex chars)\n");
    return 2;
  }

  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    std::perror("socket");
    return 1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    std::fprintf(stderr, "socket path too long: %s\n", path.c_str());
    ::close(fd);
    return 1;
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "cannot connect to tierd at %s: %s\n", path.c_str(),
                 std::strerror(errno));
    ::close(fd);
    return 1;
  }

  const auto req = tier::core::encode_admin_subscribe(*user);
  if (::send(fd, req.data(), req.size(), 0) != static_cast<ssize_t>(req.size())) {
    std::perror("send");
    ::close(fd);
    return 1;
  }
  ::shutdown(fd, SHUT_WR);  // half-close write; the daemon keeps pushing events

  const std::string me = short_id(*user);
  std::printf("streaming for user %s\n", me.c_str());
  std::fflush(stdout);

  // Events arrive as [u32 BE len][record]; accumulate and decode whole records.
  std::vector<std::uint8_t> buf;
  std::array<std::uint8_t, 4096> tmp{};
  for (;;) {
    const ssize_t n = ::recv(fd, tmp.data(), tmp.size(), 0);
    if (n < 0) {
      std::perror("recv");
      ::close(fd);
      return 1;
    }
    if (n == 0) {
      break;  // daemon closed the stream
    }
    buf.insert(buf.end(), tmp.data(), tmp.data() + n);
    for (;;) {
      if (buf.size() < 4) {
        break;
      }
      const std::uint32_t len = (static_cast<std::uint32_t>(buf[0]) << 24) |
                                (static_cast<std::uint32_t>(buf[1]) << 16) |
                                (static_cast<std::uint32_t>(buf[2]) << 8) |
                                static_cast<std::uint32_t>(buf[3]);
      if (buf.size() < 4 + len) {
        break;  // record not fully arrived yet
      }
      const auto ev = tier::core::decode_admin_stream_event(
          std::span<const std::uint8_t>(buf.data() + 4, len));
      if (ev) {
        if (ev->kind == tier::core::AdminStreamKind::message) {
          const std::string text(ev->message.payload.begin(),
                                 ev->message.payload.end());
          std::printf("from user %s  to-user %s  suite=%s  type=0x%04x  %zu bytes: %s\n",
                      short_id(ev->message.sender_user).c_str(), me.c_str(),
                      suite_name(ev->message.suite), ev->message.type,
                      ev->message.payload.size(), text.c_str());
        } else {
          std::printf("receipt %s\n", short_hex(ev->receipt.msg_id).c_str());
        }
        std::fflush(stdout);
      }
      buf.erase(buf.begin(), buf.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    }
  }
  ::close(fd);
  return 0;
}

int usage() {
  std::fputs(
      "usage: tierctl [--sock <path>] <command>\n"
      "  id                         print this node's own peer id (64 hex)\n"
      "  peers                      list the node's view of the mesh\n"
      "  send <peer-id> [suite] <message>\n"
      "                             send an encrypted node message to a peer "
      "(device)\n"
      "                             (peer-id: 64 hex chars; suite: "
      "classical|hybrid|pq, default hybrid)\n"
      "  user add [seed]            host a new user identity (optionally import a\n"
      "                             64-hex Ed25519 seed); prints its user id\n"
      "  user ls                    list the user ids hosted on this node\n"
      "  user rm <user-id>          stop hosting a user identity\n"
      "  send-user <from-user> <to-user> [suite] <message>\n"
      "                             send from a local user to a user (fans out to "
      "its online devices)\n"
      "  stream <user-id>           subscribe as a local user and print its "
      "message/receipt stream\n"
      "  status <user-id>           print a user's online status "
      "(online|offline|unknown)\n"
      "  inbox                      print and drain received node messages\n"
      "\n"
      "The socket defaults to " "/run/tierd/tierd.sock"
      ", or $TIER_ADMIN_SOCK.\n",
      stderr);
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  const char* sock_override = nullptr;
  std::vector<std::string_view> positional;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--sock") {
      if (i + 1 >= argc) {
        return usage();
      }
      sock_override = argv[++i];
    } else if (arg == "-h" || arg == "--help") {
      return usage();
    } else {
      positional.push_back(arg);
    }
  }

  const std::string path = resolve_socket(sock_override);
  const std::string_view command = positional.empty() ? "peers" : positional[0];

  if (command == "id") {
    return cmd_id(path);
  }
  if (command == "peers") {
    return cmd_peers(path);
  }
  if (command == "inbox") {
    return cmd_inbox(path);
  }
  if (command == "send") {
    // send <peer-id> <message>            (suite defaults to hybrid)
    // send <peer-id> <suite> <message>
    if (positional.size() == 3) {
      return cmd_send(path, positional[1], "hybrid", positional[2]);
    }
    if (positional.size() == 4) {
      return cmd_send(path, positional[1], positional[2], positional[3]);
    }
    return usage();
  }
  if (command == "user") {
    // user add [seed] | user ls | user rm <user-id>
    if (positional.size() >= 2 && positional[1] == "add") {
      if (positional.size() == 2) {
        return cmd_user_add(path, std::nullopt);
      }
      if (positional.size() == 3) {
        return cmd_user_add(path, positional[2]);
      }
      return usage();
    }
    if (positional.size() == 2 && positional[1] == "ls") {
      return cmd_user_list(path);
    }
    if (positional.size() == 3 && positional[1] == "rm") {
      return cmd_user_remove(path, positional[2]);
    }
    return usage();
  }
  if (command == "send-user") {
    // send-user <from-user> <to-user> <message>          (suite defaults hybrid)
    // send-user <from-user> <to-user> <suite> <message>
    if (positional.size() == 4) {
      return cmd_send_as(path, positional[1], positional[2], "hybrid",
                         positional[3]);
    }
    if (positional.size() == 5) {
      return cmd_send_as(path, positional[1], positional[2], positional[3],
                         positional[4]);
    }
    return usage();
  }
  if (command == "stream") {
    if (positional.size() == 2) {
      return cmd_stream(path, positional[1]);
    }
    return usage();
  }
  if (command == "status") {
    if (positional.size() == 2) {
      return cmd_status(path, positional[1]);
    }
    return usage();
  }
  return usage();
}
