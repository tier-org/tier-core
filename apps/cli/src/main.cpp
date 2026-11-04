// tierctl: local admin/diagnostics CLI. Talks to a running tierd over its Unix
// admin socket (one request, one response) and renders the result. Read-only
// for now: `tierctl peers` lists the node's view of the mesh.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

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

std::string roles_string(tier::core::RoleSet roles) {
  using tier::core::Role;
  struct Named { Role r; const char* name; };
  static const Named kAll[] = {{Role::client, "client"},
                               {Role::validator, "validator"},
                               {Role::keeper, "keeper"},
                               {Role::transmitter, "transmitter"}};
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
                 "not sent: peer not connected or its encryption keys unknown\n");
    return 1;
  }
  std::printf("sent (%s) to %s\n", suite_name(*suite), short_id(*id).c_str());
  return 0;
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
    std::printf("from %s  suite=%s  %zu bytes: %s\n", short_id(m.sender).c_str(),
                suite_name(m.suite), m.plaintext.size(), text.c_str());
  }
  return 0;
}

int usage() {
  std::fputs(
      "usage: tierctl [--sock <path>] <command>\n"
      "  peers                      list the node's view of the mesh\n"
      "  send <peer-id> [suite] <message>\n"
      "                             send an encrypted message to a peer\n"
      "                             (peer-id: 64 hex chars; suite: "
      "classical|hybrid|pq, default hybrid)\n"
      "  inbox                      print and drain received messages\n"
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
  return usage();
}
