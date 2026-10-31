// End-to-end over a real Unix socket: a client sends a peers request, the
// listener serves it from a handler, and the client decodes the reply. Single
// thread: connect and the request bytes are buffered before serve() runs.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "tier/core/admin.hpp"
#include "tier/net/admin_listener.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

int connect_to(const std::string& path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

int main() {
  using tier::core::Role;

  const std::string path = "tl_test.sock";  // short, relative to the test CWD

  tier::net::AdminListener listener(path);

  tier::core::PeerInfo p;
  p.id.fill(0x42);
  p.roles = tier::core::role_bit(Role::validator);
  p.incarnation = 7;
  p.liveness = tier::core::Liveness::alive;
  p.addresses = {"[2001:db8::42]:7777"};
  const std::vector<tier::core::PeerInfo> peers{p};
  const std::vector<tier::core::PeerId> connected{p.id};

  const auto handler =
      [&](tier::core::AdminOp op) -> std::vector<std::uint8_t> {
    if (op == tier::core::AdminOp::peers) {
      return tier::core::encode_admin_peers(peers, connected);
    }
    return {};
  };

  const int fd = connect_to(path);
  check(fd >= 0, "client connects to the admin socket");
  if (fd < 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }

  const auto req = tier::core::encode_admin_request(tier::core::AdminOp::peers);
  check(::send(fd, req.data(), req.size(), 0) == static_cast<ssize_t>(req.size()),
        "client sends the request");
  ::shutdown(fd, SHUT_WR);

  listener.serve(handler);  // accept + reply

  std::vector<std::uint8_t> reply;
  std::uint8_t buf[512];
  for (;;) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      break;
    }
    reply.insert(reply.end(), buf, buf + n);
  }
  ::close(fd);

  const auto decoded = tier::core::decode_admin_peers(reply);
  check(decoded.has_value(), "client decodes the reply");
  check(decoded && decoded->size() == 1, "one peer in the reply");
  if (decoded && decoded->size() == 1) {
    check((*decoded)[0].info.id == p.id, "peer id round-trips over the socket");
    check((*decoded)[0].connected, "peer reported connected");
  }

  // A second request on a fresh connection still works (listener is reusable).
  const int fd2 = connect_to(path);
  check(fd2 >= 0, "second client connects");
  if (fd2 >= 0) {
    ::send(fd2, req.data(), req.size(), 0);
    ::shutdown(fd2, SHUT_WR);
    listener.serve(handler);
    std::vector<std::uint8_t> reply2;
    for (;;) {
      const ssize_t n = ::recv(fd2, buf, sizeof(buf), 0);
      if (n <= 0) {
        break;
      }
      reply2.insert(reply2.end(), buf, buf + n);
    }
    ::close(fd2);
    check(tier::core::decode_admin_peers(reply2).has_value(),
          "second reply decodes");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
