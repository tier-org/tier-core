#include "tier/net/node.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tier/core/control.hpp"
#include "tier/crypto/hash.hpp"

namespace tier::net {
namespace {

// How many distinct peers must agree on our observed address before we adopt
// it. One is enough to bootstrap from a single seed; raising it hardens against
// a lying peer, and belongs with signed membership (not yet in place).
constexpr std::size_t kAddressConfirmations = 1;

// Minimum gap between dial attempts to the same address.
constexpr auto kDialRetry = std::chrono::seconds(2);

// Split a dialable "ip:port" (IPv6 bracketed as "[::1]:443") into host and
// port. Returns std::nullopt on anything malformed - these strings arrive over
// gossip and are untrusted.
std::optional<std::pair<std::string, std::uint16_t>> split_host_port(
    const std::string& addr) {
  std::string host;
  std::string_view port_sv;
  if (!addr.empty() && addr.front() == '[') {
    const auto close = addr.find(']');
    if (close == std::string::npos || close + 1 >= addr.size() ||
        addr[close + 1] != ':') {
      return std::nullopt;
    }
    host = addr.substr(1, close - 1);
    port_sv = std::string_view(addr).substr(close + 2);
  } else {
    const auto colon = addr.rfind(':');
    if (colon == std::string::npos || colon == 0) {
      return std::nullopt;
    }
    host = addr.substr(0, colon);
    port_sv = std::string_view(addr).substr(colon + 1);
  }
  unsigned value = 0;
  const auto* const end = port_sv.data() + port_sv.size();
  const auto res = std::from_chars(port_sv.data(), end, value);
  if (res.ec != std::errc{} || res.ptr != end || value == 0 || value > 65535) {
    return std::nullopt;
  }
  return std::make_pair(std::move(host), static_cast<std::uint16_t>(value));
}

// Addresses we never dial: unset, or a wildcard a peer has not yet corrected.
bool is_dialable(const std::string& addr) {
  if (addr.empty()) {
    return false;
  }
  return addr.rfind("0.0.0.0:", 0) != 0 && addr.rfind("[::]:", 0) != 0;
}

}  // namespace

Node::Node(tier::crypto::NodeIdentity identity, tier::core::Role role,
           const std::string& ip, std::uint16_t port,
           tier::core::SwimConfig swim)
    : identity_(std::move(identity)),
      self_id_(tier::crypto::sha256(identity_.public_key())),
      endpoint_(identity_, ip, port),
      fd_(self_id_, membership_, swim,
          [this](const tier::core::PeerId& to,
                 const std::vector<std::uint8_t>& msg) {
            const auto it = conn_by_peer_.find(to);
            if (it != conn_by_peer_.end()) {
              endpoint_.send(it->second, msg);
            }
          }) {
  self_address_ = ip + ":" + std::to_string(endpoint_.local_port());

  tier::core::PeerInfo me;
  me.id = self_id_;
  me.address = self_address_;
  me.role = role;
  me.incarnation = 1;
  me.liveness = tier::core::Liveness::alive;
  membership_.apply(me);

  endpoint_.on_handshake([this](ConnId conn, bool, const PeerId&) {
    push_membership(conn);
    // Tell the peer where we see it: it binds a wildcard and otherwise cannot
    // learn its own reachable address.
    if (const auto addr = endpoint_.remote_address(conn)) {
      endpoint_.send(conn, tier::core::encode_observed_addr(*addr));
    }
  });
  endpoint_.on_message([this](ConnId, const PeerId& key,
                              std::span<const tier::crypto::Byte> payload) {
    const tier::core::PeerId from = tier::crypto::sha256(key);
    if (tier::core::peek_control_type(payload) ==
        tier::core::ControlType::observed_addr) {
      handle_observed(from, payload);
      return;
    }
    if (fd_.handle(std::chrono::steady_clock::now(), from, payload)) {
      return;  // consumed as a SWIM probe message
    }
    merge_message(payload);
  });
}

std::uint16_t Node::local_port() const noexcept { return endpoint_.local_port(); }

const tier::core::PeerId& Node::peer_id() const noexcept { return self_id_; }

const tier::core::Membership& Node::membership() const noexcept {
  return membership_;
}

void Node::connect(const std::string& ip, std::uint16_t port) {
  endpoint_.connect(ip, port);
  // Record it so autodial does not open a second connection to the same peer
  // while this handshake is still in flight.
  dialed_[ip + ":" + std::to_string(port)] = std::chrono::steady_clock::now();
}

std::vector<tier::core::PeerId> Node::connected_peers() const {
  std::vector<tier::core::PeerId> ids;
  ids.reserve(conn_by_peer_.size());
  for (const auto& [id, conn] : conn_by_peer_) {
    ids.push_back(id);
  }
  return ids;
}

void Node::on_membership_change(
    std::function<void(const tier::core::PeerInfo&)> cb) {
  on_change_ = std::move(cb);
}

void Node::poll(int timeout_ms) {
  endpoint_.poll(timeout_ms);

  // Refresh the peer->connection routing and the neighbor set from the live
  // connections; reaped connections drop out here on their own.
  conn_by_peer_.clear();
  std::vector<tier::core::PeerId> neighbors;
  for (const auto& [conn, key] : endpoint_.connections()) {
    const tier::core::PeerId id = tier::crypto::sha256(key);
    conn_by_peer_[id] = conn;
    neighbors.push_back(id);
  }

  const auto now = std::chrono::steady_clock::now();
  autodial(now);
  fd_.tick(now, neighbors);

  // Periodic anti-entropy: push the current snapshot to all peers so the view
  // (including liveness changes the detector made) stays fresh and propagates
  // transitively through a seed.
  constexpr auto kGossipInterval = std::chrono::milliseconds(100);
  if (now - last_gossip_ >= kGossipInterval) {
    endpoint_.broadcast(tier::core::encode_membership_message(membership_.snapshot()));
    last_gossip_ = now;
  }
}

void Node::push_membership(ConnId conn) {
  endpoint_.send(conn,
                 tier::core::encode_membership_message(membership_.snapshot()));
}

void Node::merge_message(std::span<const tier::crypto::Byte> payload) {
  const auto decoded = tier::core::decode_membership_message(payload);
  if (!decoded) {
    return;
  }
  for (const tier::core::PeerInfo& peer : *decoded) {
    if (membership_.apply(peer) && on_change_) {
      on_change_(peer);
    }
  }
}

void Node::handle_observed(const tier::core::PeerId& from,
                           std::span<const tier::crypto::Byte> payload) {
  const auto msg = tier::core::decode_observed_addr(payload);
  if (!msg || !is_dialable(msg->address)) {
    return;
  }
  observed_[from] = msg->address;

  // Tally reports and take the most-agreed address.
  std::map<std::string, std::size_t> tally;
  const std::string* best = nullptr;
  std::size_t best_count = 0;
  for (const auto& [peer, addr] : observed_) {
    const std::size_t n = ++tally[addr];
    if (n > best_count) {
      best_count = n;
      best = &tally.find(addr)->first;
    }
  }
  if (best == nullptr || best_count < kAddressConfirmations) {
    return;
  }

  const auto self = membership_.find(self_id_);
  if (!self || self->address == *best) {
    return;  // already advertising this address
  }
  // Adopt it: raise our incarnation so the new address supersedes the old one
  // everywhere (same mechanism SWIM uses to refute a stale report).
  tier::core::PeerInfo me = *self;
  me.address = *best;
  me.incarnation += 1;
  me.liveness = tier::core::Liveness::alive;
  self_address_ = me.address;
  membership_.apply(me);
  if (on_change_) {
    on_change_(me);
  }
}

void Node::autodial(std::chrono::steady_clock::time_point now) {
  for (const tier::core::PeerInfo& p : membership_.snapshot()) {
    if (p.id == self_id_ || p.liveness == tier::core::Liveness::dead ||
        !is_dialable(p.address) || conn_by_peer_.count(p.id) != 0) {
      continue;
    }
    // Tie-break: only the lower id dials, so a pair ends up with one connection
    // rather than two crossing ones.
    if (!(self_id_ < p.id)) {
      continue;
    }
    const auto seen = dialed_.find(p.address);
    if (seen != dialed_.end() && now - seen->second < kDialRetry) {
      continue;
    }
    dialed_[p.address] = now;
    const auto hp = split_host_port(p.address);
    if (!hp) {
      continue;
    }
    try {
      endpoint_.connect(hp->first, hp->second);
    } catch (const std::exception&) {
      // A malformed or unroutable gossiped address must not take us down; the
      // backoff above keeps us from retrying it in a tight loop.
    }
  }
}

}  // namespace tier::net
