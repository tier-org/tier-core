#include "tier/net/node.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <set>
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
  // A real dial string starts with a host: an IPv4 digit or a bracketed "[".
  // Anything starting with ':' has no host - ":port" (empty bind) or ":::port"
  // (the "::" wildcard glued to a port) - and is never a reachable address.
  if (addr.empty() || addr.front() == ':') {
    return false;
  }
  return addr.rfind("0.0.0.0:", 0) != 0 && addr.rfind("[::]:", 0) != 0;
}

// An IPv6 "ip:port" is bracketed ("[::1]:443"); anything else is treated as
// IPv4. Used only to order dial candidates (prefer IPv6), never for parsing.
bool is_ipv6(const std::string& addr) {
  return !addr.empty() && addr.front() == '[';
}

}  // namespace

Node::Node(tier::crypto::NodeIdentity identity, tier::core::RoleSet roles,
           const std::string& ip, std::uint16_t port,
           tier::core::SwimConfig swim, std::string network)
    : identity_(std::move(identity)),
      self_id_(tier::crypto::sha256(identity_.public_key())),
      endpoint_(identity_, ip, port, network),
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
  // Advertise a bind address only if it is concrete. On a wildcard bind ("::"
  // or "0.0.0.0") self_address_ is not a reachable address, so start with an
  // empty set and adopt the real one once a peer reports it (handle_observed).
  if (is_dialable(self_address_)) {
    me.addresses = {self_address_};
  }
  me.roles = roles;
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

void Node::bootstrap(const std::vector<std::string>& seeds) {
  const auto now = std::chrono::steady_clock::now();
  const auto self = membership_.find(self_id_);
  for (const std::string& addr : seeds) {
    if (!is_dialable(addr)) {
      continue;
    }
    // Do not dial ourselves. We only know our own address if we were bound to a
    // concrete IP (self_address_) or have already adopted advertised ones; on a
    // wildcard bind neither matches our public address yet, so a self-dial is
    // still possible here and is dropped later by the self guard in poll().
    if (addr == self_address_) {
      continue;
    }
    if (self && std::find(self->addresses.begin(), self->addresses.end(),
                          addr) != self->addresses.end()) {
      continue;
    }
    const auto hp = split_host_port(addr);
    if (!hp) {
      continue;
    }
    try {
      endpoint_.connect(hp->first, hp->second);
    } catch (const std::exception&) {
      continue;  // an unroutable seed must not take us down
    }
    // Key the backoff by the canonical bracketed address so a seed we later
    // learn over gossip is not immediately redialed by autodial.
    dialed_[addr] = now;
  }
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
    // Never route to or treat ourselves as a neighbor. A node that is itself a
    // seed can dial its own public address before it knows that address is its
    // own; drop any such self-connection here rather than probe or gossip to it.
    if (id == self_id_) {
      continue;
    }
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

std::vector<std::string> Node::confirmed_addresses(
    const std::map<tier::core::PeerId, std::set<std::string>>& observed,
    std::size_t threshold) {
  // Count distinct reporting peers per address. A peer's set contributes each
  // of its addresses once, so a single dual-stack peer backs both families.
  std::map<std::string, std::size_t> tally;
  for (const auto& [peer, addrs] : observed) {
    for (const std::string& addr : addrs) {
      ++tally[addr];
    }
  }
  std::vector<std::string> confirmed;
  for (const auto& [addr, n] : tally) {
    if (n >= threshold) {
      confirmed.push_back(addr);  // std::map keeps these sorted and unique
    }
  }
  return confirmed;
}

void Node::handle_observed(const tier::core::PeerId& from,
                           std::span<const tier::crypto::Byte> payload) {
  const auto msg = tier::core::decode_observed_addr(payload);
  if (!msg || !is_dialable(msg->address)) {
    return;
  }
  // Accumulate every address a peer reports, not just the last one. A peer that
  // has connected to us over both families reports each; overwriting here would
  // collapse a dial-only node (one that only ever receives connections, e.g. the
  // highest-id peer) to whichever family it was most recently dialed over, so it
  // would advertise a single family even though both are reachable.
  observed_[from].insert(msg->address);

  // Advertise every address confirmed by enough peers, not just one: a
  // dual-stack node is seen at its IPv4 address by IPv4 peers and at its IPv6
  // address by IPv6 peers, and must advertise both so either family can reach it.
  std::vector<std::string> confirmed =
      confirmed_addresses(observed_, kAddressConfirmations);
  if (confirmed.empty()) {
    return;
  }
  // Keep any dialable address we were started with (e.g. a concrete bind IP)
  // alongside the observed ones.
  if (is_dialable(self_address_) &&
      std::find(confirmed.begin(), confirmed.end(), self_address_) ==
          confirmed.end()) {
    confirmed.push_back(self_address_);
    std::sort(confirmed.begin(), confirmed.end());
  }

  const auto self = membership_.find(self_id_);
  if (!self || self->addresses == confirmed) {
    return;  // already advertising exactly this set
  }
  // Adopt it: raise our incarnation so the new address set supersedes the old
  // one everywhere (the same mechanism SWIM uses to refute a stale report).
  tier::core::PeerInfo me = *self;
  me.addresses = std::move(confirmed);
  me.incarnation += 1;
  me.liveness = tier::core::Liveness::alive;
  membership_.apply(me);
  if (on_change_) {
    on_change_(me);
  }
}

std::optional<std::string> Node::select_dial_candidate(
    const std::vector<std::string>& candidates,
    const std::map<std::string, std::chrono::steady_clock::time_point>& dialed,
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::duration retry) {
  using Clock = std::chrono::steady_clock;

  std::vector<const std::string*> dialable;
  for (const std::string& addr : candidates) {
    if (is_dialable(addr)) {
      dialable.push_back(&addr);
    }
  }
  if (dialable.empty()) {
    return std::nullopt;
  }

  // Serialize attempts to this peer: if any candidate was tried within `retry`,
  // wait for it rather than opening a second connection to the same peer.
  Clock::time_point last_attempt = Clock::time_point::min();
  for (const std::string* addr : dialable) {
    const auto it = dialed.find(*addr);
    if (it != dialed.end()) {
      last_attempt = std::max(last_attempt, it->second);
    }
  }
  if (last_attempt != Clock::time_point::min() && now - last_attempt < retry) {
    return std::nullopt;
  }

  // Pick the least-recently dialed candidate (never-dialed sorts oldest), so
  // attempts rotate across families; prefer IPv6 on a tie.
  const std::string* best = nullptr;
  Clock::time_point best_when{};
  for (const std::string* addr : dialable) {
    const auto it = dialed.find(*addr);
    const Clock::time_point when =
        it != dialed.end() ? it->second : Clock::time_point::min();
    bool better = false;
    if (best == nullptr) {
      better = true;
    } else if (when != best_when) {
      better = when < best_when;
    } else {
      better = is_ipv6(*addr) && !is_ipv6(*best);  // tie: prefer IPv6
    }
    if (better) {
      best = addr;
      best_when = when;
    }
  }
  return *best;
}

void Node::autodial(std::chrono::steady_clock::time_point now) {
  for (const tier::core::PeerInfo& p : membership_.snapshot()) {
    if (p.id == self_id_ || p.liveness == tier::core::Liveness::dead ||
        conn_by_peer_.count(p.id) != 0) {
      continue;
    }
    // Tie-break: only the lower id dials, so a pair ends up with one connection
    // rather than two crossing ones.
    if (!(self_id_ < p.id)) {
      continue;
    }
    const auto chosen = select_dial_candidate(p.addresses, dialed_, now, kDialRetry);
    if (!chosen) {
      continue;
    }
    dialed_[*chosen] = now;
    const auto hp = split_host_port(*chosen);
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
