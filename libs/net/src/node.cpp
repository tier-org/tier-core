#include "tier/net/node.hpp"

#include <chrono>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "tier/core/control.hpp"
#include "tier/crypto/hash.hpp"

namespace tier::net {

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

  endpoint_.on_handshake(
      [this](ConnId conn, bool, const PeerId&) { push_membership(conn); });
  endpoint_.on_message([this](ConnId, const PeerId& key,
                              std::span<const tier::crypto::Byte> payload) {
    const tier::core::PeerId from = tier::crypto::sha256(key);
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

}  // namespace tier::net
