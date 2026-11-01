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
bool query(const std::string& path, tier::core::AdminOp op,
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

  const auto req = tier::core::encode_admin_request(op);
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
  const auto peers = tier::core::decode_admin_peers(reply);
  if (!peers) {
    std::fprintf(stderr, "malformed response from tierd\n");
    return 1;
  }

  std::size_t connected = 0;
  for (const auto& p : *peers) {
    if (p.connected) {
      ++connected;
    }
  }
  std::printf("known=%zu connected=%zu\n\n", peers->size(), connected);
  std::printf("%-16s  %-4s  %-8s  %-22s  %-10s  %s\n", "PEER", "CONN",
              "LIVENESS", "ROLES", "VERSION", "ADDRESSES");
  for (const auto& p : *peers) {
    std::printf("%-16s  %-4s  %-8s  %-22s  %-10s  %s\n",
                short_id(p.info.id).c_str(), p.connected ? "yes" : "no",
                liveness_string(p.info.liveness),
                roles_string(p.info.roles).c_str(),
                p.info.version.empty() ? "-" : p.info.version.c_str(),
                join_addresses(p.info.addresses).c_str());
  }
  return 0;
}

int usage() {
  std::fputs(
      "usage: tierctl [--sock <path>] peers\n"
      "  peers   list the node's view of the mesh (known/connected)\n"
      "\n"
      "The socket defaults to " "/run/tierd/tierd.sock"
      ", or $TIER_ADMIN_SOCK.\n",
      stderr);
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  const char* sock_override = nullptr;
  std::string_view command = "peers";

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
      command = arg;
    }
  }

  const std::string path = resolve_socket(sock_override);
  if (command == "peers") {
    return cmd_peers(path);
  }
  return usage();
}
