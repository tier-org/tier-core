#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/core/swim.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/net/endpoint.hpp"

namespace tier::net {

// A network participant: a QUIC endpoint plus the membership view it maintains.
// On every connection the two peers exchange their membership snapshots and
// merge them (anti-entropy, one round for now). This is the control plane of
// the base layer; it carries node identities, roles and liveness, never user
// application messages.
class Node {
 public:
  Node(tier::crypto::NodeIdentity identity, tier::core::Role role,
       const std::string& ip, std::uint16_t port,
       tier::core::SwimConfig swim = {});

  [[nodiscard]] std::uint16_t local_port() const noexcept;

  // This node's membership id: SHA-256 of its public key.
  [[nodiscard]] const tier::core::PeerId& peer_id() const noexcept;

  void connect(const std::string& ip, std::uint16_t port);
  void poll(int timeout_ms);

  [[nodiscard]] const tier::core::Membership& membership() const noexcept;

  // Peers this node currently holds a live connection to (handshake complete).
  [[nodiscard]] std::vector<tier::core::PeerId> connected_peers() const;

  // Invoked whenever a membership entry is newly learned or updated by a merge.
  void on_membership_change(std::function<void(const tier::core::PeerInfo&)> cb);

 private:
  void push_membership(ConnId conn);
  void merge_message(std::span<const tier::crypto::Byte> payload);
  // Record a peer's report of the address it observes us at; adopt it as our
  // advertised address once enough peers agree.
  void handle_observed(const tier::core::PeerId& from,
                       std::span<const tier::crypto::Byte> payload);
  // Dial known peers we have learned of but are not yet connected to, forming a
  // mesh out of transitive discovery.
  void autodial(std::chrono::steady_clock::time_point now);

  tier::crypto::NodeIdentity identity_;
  tier::core::PeerId self_id_;
  tier::core::Membership membership_;
  Endpoint endpoint_;
  std::string self_address_;
  std::function<void(const tier::core::PeerInfo&)> on_change_;
  std::chrono::steady_clock::time_point last_gossip_{};
  // Peer id -> live connection, rebuilt from the endpoint each poll; the failure
  // detector sends probes by peer id and this routes them.
  std::map<tier::core::PeerId, ConnId> conn_by_peer_;
  // Per reporting peer, the address it claims to observe us at (observed_addr).
  std::map<tier::core::PeerId, std::string> observed_;
  // Per dialed "ip:port", when we last issued a connect, to rate-limit redials
  // and avoid a duplicate connection to a peer whose handshake is still pending.
  std::map<std::string, std::chrono::steady_clock::time_point> dialed_;
  tier::core::FailureDetector fd_;
};

}  // namespace tier::net
