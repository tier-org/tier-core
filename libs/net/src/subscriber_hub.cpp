#include "tier/net/subscriber_hub.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <vector>

namespace tier::net {
namespace {

bool write_all(int fd, const std::uint8_t* data, std::size_t len) noexcept {
  std::size_t off = 0;
  while (off < len) {
    const ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
    if (n <= 0) {
      return false;  // timeout, closed peer, or error
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

SubscriberHub::~SubscriberHub() { close_all(); }

void SubscriberHub::add(const tier::core::PeerId& user, int fd) {
  subs_.emplace(user, fd);
}

bool SubscriberHub::has(const tier::core::PeerId& user) const {
  return subs_.find(user) != subs_.end();
}

std::size_t SubscriberHub::publish(const tier::core::PeerId& user,
                                   std::span<const std::uint8_t> record) {
  // [u32 BE len][record], built once and sent to each subscriber of this user.
  std::vector<std::uint8_t> framed;
  framed.reserve(4 + record.size());
  const auto len = static_cast<std::uint32_t>(record.size());
  framed.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFFU));
  framed.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFFU));
  framed.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFFU));
  framed.push_back(static_cast<std::uint8_t>(len & 0xFFU));
  framed.insert(framed.end(), record.begin(), record.end());

  std::size_t delivered = 0;
  auto range = subs_.equal_range(user);
  for (auto it = range.first; it != range.second;) {
    if (write_all(it->second, framed.data(), framed.size())) {
      ++delivered;
      ++it;
    } else {
      ::close(it->second);
      it = subs_.erase(it);
    }
  }
  return delivered;
}

void SubscriberHub::close_all() {
  for (const auto& [user, fd] : subs_) {
    ::close(fd);
  }
  subs_.clear();
}

}  // namespace tier::net
