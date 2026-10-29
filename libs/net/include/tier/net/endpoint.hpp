#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"

namespace tier::net {

// A peer's network identity is its Ed25519 public key, taken from the
// certificate it presents in the QUIC/TLS handshake (the libp2p-TLS pattern).
using PeerId = tier::crypto::Ed25519PublicKey;

// A QUIC endpoint: one UDP socket that both accepts incoming connections
// (server role) and dials out (client role), each side authenticated by its
// node certificate over mutual TLS 1.3. v0 is deliberately minimal -a single
// local UDP path, connections matched by remote address, no Retry/migration.
class Endpoint {
 public:
  // Bind a UDP socket to ip:port (port 0 = ephemeral). Throws std::runtime_error
  // on socket or TLS setup failure.
  Endpoint(const tier::crypto::NodeIdentity& identity, const std::string& ip,
           std::uint16_t port);
  ~Endpoint();

  Endpoint(const Endpoint&) = delete;
  Endpoint& operator=(const Endpoint&) = delete;
  Endpoint(Endpoint&&) = delete;
  Endpoint& operator=(Endpoint&&) = delete;

  // The actual bound UDP port (meaningful when binding to ephemeral port 0).
  [[nodiscard]] std::uint16_t local_port() const noexcept;

  // Begin a client connection to ip:port. Throws std::runtime_error on failure.
  void connect(const std::string& ip, std::uint16_t port);

  // Run one I/O cycle: wait up to timeout_ms for a datagram or a QUIC timer,
  // then process reads, flush writes and handle expiries.
  void poll(int timeout_ms);

  // Number of connections that have completed their TLS handshake.
  [[nodiscard]] std::size_t completed_handshakes() const noexcept;

  // Invoked once per connection when its handshake completes, with the peer's
  // authenticated identity.
  void on_handshake(std::function<void(const PeerId&)> callback);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tier::net
