#include "tier/net/admin_listener.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace tier::net {
namespace {

// Per-connection I/O bound: a request/response is a few hundred bytes and the
// peer is local, so a stuck client is capped at this before we drop it. Keeps
// serve() from ever blocking the node loop for long.
constexpr int kIoTimeoutMs = 100;

// A request is tiny ([version:1][op:1]); never read more than this from a
// client, so a flood cannot grow our buffer.
constexpr std::size_t kMaxRequest = 16;

void set_io_timeout(int fd) noexcept {
  timeval tv{};
  tv.tv_sec = kIoTimeoutMs / 1000;
  tv.tv_usec = (kIoTimeoutMs % 1000) * 1000;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool write_all(int fd, const std::vector<std::uint8_t>& data) noexcept {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0) {
      return false;  // timeout, closed peer, or error
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

AdminListener::AdminListener(std::string path) : path_(std::move(path)) {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path_.size() + 1 > sizeof(addr.sun_path)) {
    throw std::runtime_error("admin socket path too long: " + path_);
  }
  std::memcpy(addr.sun_path, path_.c_str(), path_.size() + 1);

  // Remove a stale socket file from a previous run; ignore if absent.
  ::unlink(path_.c_str());

  fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd_ < 0) {
    throw std::runtime_error("admin socket() failed");
  }
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd_);
    fd_ = -1;
    throw std::runtime_error("admin bind() failed: " + path_);
  }
  if (::listen(fd_, 8) != 0) {
    ::close(fd_);
    fd_ = -1;
    ::unlink(path_.c_str());
    throw std::runtime_error("admin listen() failed");
  }
  // Service user and root only; the directory's own permissions are the outer
  // gate (systemd RuntimeDirectory).
  ::chmod(path_.c_str(), 0660);
}

AdminListener::~AdminListener() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
  if (!path_.empty()) {
    ::unlink(path_.c_str());
  }
}

void AdminListener::serve(const Handler& handler, int max_conns) {
  for (int i = 0; i < max_conns; ++i) {
    const int conn = ::accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (conn < 0) {
      return;  // EAGAIN: no more pending connections
    }
    set_io_timeout(conn);

    // Read the (tiny) request. The client sends it then half-closes, so a
    // single bounded read is enough; stop at kMaxRequest regardless.
    std::array<std::uint8_t, kMaxRequest> buf{};
    const ssize_t n = ::recv(conn, buf.data(), buf.size(), 0);
    if (n > 0) {
      const auto op = tier::core::decode_admin_request(
          std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)));
      if (op) {
        const std::vector<std::uint8_t> reply = handler(*op);
        if (!reply.empty()) {
          write_all(conn, reply);
        }
      }
    }
    ::close(conn);
  }
}

}  // namespace tier::net
