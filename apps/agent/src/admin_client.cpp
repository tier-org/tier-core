#include "admin_client.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <random>
#include <span>

#include "tier/app/frame.hpp"
#include "tier/app/registry.hpp"
#include "tier/msg/sealed.hpp"

namespace tier::agent {
namespace {

int connect_unix(const std::string& path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    ::close(fd);
    return -1;
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

bool send_all(int fd, const std::uint8_t* data, std::size_t len) {
  std::size_t off = 0;
  while (off < len) {
    const ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
    if (n <= 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> AdminClient::query(
    const std::vector<std::uint8_t>& req) {
  const int fd = connect_unix(path_);
  if (fd < 0) return std::nullopt;
  if (!send_all(fd, req.data(), req.size())) {
    ::close(fd);
    return std::nullopt;
  }
  ::shutdown(fd, SHUT_WR);
  std::vector<std::uint8_t> out;
  std::array<std::uint8_t, 4096> buf{};
  for (;;) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) {
      ::close(fd);
      return std::nullopt;
    }
    if (n == 0) break;
    out.insert(out.end(), buf.data(), buf.data() + n);
  }
  ::close(fd);
  return out;
}

std::optional<tier::core::PeerId> AdminClient::add_user(
    const std::array<std::uint8_t, 32>& seed) {
  const auto reply = query(tier::core::encode_admin_user_add(seed));
  if (!reply) return std::nullopt;
  const auto rep = tier::core::decode_admin_user_add_reply(
      std::span<const std::uint8_t>(reply->data(), reply->size()));
  if (!rep || !rep->ok) return std::nullopt;
  return rep->user_id;
}

tier::core::SendStatus AdminClient::send_telemetry(
    const tier::core::PeerId& from_user, const tier::core::PeerId& to_user,
    const std::vector<std::uint8_t>& envelope) {
  tier::app::AppFrame frame;
  frame.type = tier::app::AppType::telemetry;
  frame.flags = 0;  // metrics are fire-and-forget; no delivery receipt
  {
    std::random_device rd;
    for (auto& b : frame.msg_id) b = static_cast<std::uint8_t>(rd());
  }
  frame.payload = envelope;
  const auto framed = tier::app::encode_app_frame(frame);
  if (framed.size() > tier::core::kMaxAdminMessageBytes) {
    return tier::core::SendStatus::failed;
  }
  const auto req = tier::core::encode_admin_send_as(
      from_user, to_user, static_cast<std::uint8_t>(tier::msg::Suite::hybrid),
      std::span<const std::uint8_t>(framed.data(), framed.size()));
  const auto reply = query(req);
  if (!reply) return tier::core::SendStatus::failed;
  const auto status = tier::core::decode_admin_send_as_reply(
      std::span<const std::uint8_t>(reply->data(), reply->size()));
  return status.value_or(tier::core::SendStatus::failed);
}

int AdminClient::open_stream(const tier::core::PeerId& user) {
  const int fd = connect_unix(path_);
  if (fd < 0) return -1;
  const auto req = tier::core::encode_admin_subscribe(user);
  if (!send_all(fd, req.data(), req.size())) {
    ::close(fd);
    return -1;
  }
  ::shutdown(fd, SHUT_WR);  // half-close write; keep reading events
  return fd;
}

void StreamParser::feed(const std::uint8_t* data, std::size_t n) {
  buf_.insert(buf_.end(), data, data + n);
}

std::optional<tier::core::AdminStreamEvent> StreamParser::next() {
  while (buf_.size() >= 4) {
    const std::uint32_t len = (static_cast<std::uint32_t>(buf_[0]) << 24) |
                              (static_cast<std::uint32_t>(buf_[1]) << 16) |
                              (static_cast<std::uint32_t>(buf_[2]) << 8) |
                              static_cast<std::uint32_t>(buf_[3]);
    if (buf_.size() < 4 + static_cast<std::size_t>(len)) return std::nullopt;
    auto ev = tier::core::decode_admin_stream_event(
        std::span<const std::uint8_t>(buf_.data() + 4, len));
    buf_.erase(buf_.begin(), buf_.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    if (ev) return ev;
  }
  return std::nullopt;
}

}  // namespace tier::agent
