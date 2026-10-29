#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"

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

  // Name of the key-exchange group negotiated by the most recently completed
  // handshake (e.g. "X25519MLKEM768"), or empty if none has completed.
  [[nodiscard]] std::string last_negotiated_group() const;

  // Invoked once per connection when its handshake completes, with the peer's
  // authenticated identity.
  void on_handshake(std::function<void(const PeerId&)> callback);

  // Invoked for each application message (one length-prefixed frame) received
  // on a connection, with the peer's identity and the frame payload.
  void on_message(
      std::function<void(const PeerId&, std::span<const tier::crypto::Byte>)> callback);

  // Demo/base-layer behaviour for the walking skeleton:
  //  - a client connection, once its handshake completes, opens one bidi stream
  //    and sends this payload as a single frame (empty = send nothing);
  //  - a server connection echoes every received frame back on the same stream.
  void set_auto_ping(std::vector<tier::crypto::Byte> payload);
  void set_auto_echo(bool enabled);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tier::net
