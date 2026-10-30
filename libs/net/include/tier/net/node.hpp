#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

#include "tier/core/membership.hpp"
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
       const std::string& ip, std::uint16_t port);

  [[nodiscard]] std::uint16_t local_port() const noexcept;

  // This node's membership id: SHA-256 of its public key.
  [[nodiscard]] const tier::core::PeerId& peer_id() const noexcept;

  void connect(const std::string& ip, std::uint16_t port);
  void poll(int timeout_ms);

  [[nodiscard]] const tier::core::Membership& membership() const noexcept;

  // Invoked whenever a membership entry is newly learned or updated by a merge.
  void on_membership_change(std::function<void(const tier::core::PeerInfo&)> cb);

 private:
  void push_membership(ConnId conn);
  void merge_message(std::span<const tier::crypto::Byte> payload);

  tier::crypto::NodeIdentity identity_;
  tier::core::PeerId self_id_;
  tier::core::Membership membership_;
  Endpoint endpoint_;
  std::string self_address_;
  std::function<void(const tier::core::PeerInfo&)> on_change_;
  std::chrono::steady_clock::time_point last_gossip_{};
};

}  // namespace tier::net
