#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"

namespace tier::net {

// A peer's network identity is its Ed25519 public key, taken from the
// certificate it presents in the QUIC/TLS handshake (the libp2p-TLS pattern).
using PeerId = tier::crypto::Ed25519PublicKey;

// Opaque handle to one connection owned by an Endpoint.
using ConnId = std::uint64_t;

// A QUIC endpoint: one UDP socket that both accepts incoming connections
// (server role) and dials out (client role), each side authenticated by its
// node certificate over mutual TLS 1.3. v0 is deliberately minimal -a single
// local UDP path, connections matched by remote address, no Retry/migration.
class Endpoint {
 public:
  // Bind a UDP socket to ip:port (port 0 = ephemeral). Throws std::runtime_error
  // on socket or TLS setup failure. `network` selects the cluster: it is folded
  // into the ALPN token, so peers on different networks cannot complete a
  // handshake (see tier::core networks). Defaults to the mainnet cluster.
  Endpoint(const tier::crypto::NodeIdentity& identity, const std::string& ip,
           std::uint16_t port, const std::string& network = "mainnet");
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

  // Snapshot of the currently live connections (handshake complete, not
  // closing), as (handle, peer identity). The caller rebuilds its peer->conn
  // routing and neighbor set from this each cycle, so reaped connections drop
  // out on their own.
  [[nodiscard]] std::vector<std::pair<ConnId, PeerId>> connections() const;

  // The remote address of a connection as this endpoint observes it on the
  // wire ("ip:port"), or std::nullopt if the handle is unknown. This is what we
  // report to the peer so it can learn its own reachable address.
  [[nodiscard]] std::optional<std::string> remote_address(ConnId conn) const;

  // Name of the key-exchange group negotiated by the most recently completed
  // handshake (e.g. "X25519MLKEM768"), or empty if none has completed.
  [[nodiscard]] std::string last_negotiated_group() const;

  // Invoked once per connection when its handshake completes, with the
  // connection handle, whether we initiated it (dialed), and the peer's
  // authenticated identity.
  void on_handshake(
      std::function<void(ConnId, bool initiator, const PeerId&)> callback);

  // Invoked for each application message (one length-prefixed frame) received
  // on a connection, with the connection handle, the peer's identity, and the
  // frame payload.
  void on_message(
      std::function<void(ConnId, const PeerId&, std::span<const tier::crypto::Byte>)>
          callback);

  // Queue one length-prefixed frame to send on a connection. A bidi stream is
  // opened lazily on first send if we initiated the connection.
  void send(ConnId conn, std::span<const tier::crypto::Byte> payload);

  // Queue a frame on every connection whose handshake has completed.
  void broadcast(std::span<const tier::crypto::Byte> payload);

  // Test-only: simulate an address-restricted-cone NAT in front of this
  // endpoint. When on, an inbound datagram from a source this endpoint has not
  // yet sent a packet to is dropped (as a real NAT would, having no mapping for
  // it). This makes a plain one-sided dial to a NAT'd peer fail and a
  // coordinated hole punch succeed, so NAT traversal can be tested without a
  // real NAT. Off in production; never set on a live node.
  void set_simulated_restricted_nat(bool on);

  // Test-only: simulate a lossy link on this endpoint. Each datagram it would
  // send or receive is independently dropped with probability `prob` (0 = clean,
  // 1 = full partition), using a PRNG seeded with `seed` for reproducibility.
  // QUIC's loss recovery then has to carry delivery, so presence, resolution, and
  // message delivery can be tested under packet loss and partition without a real
  // degraded network. Off in production; never set on a live node.
  void set_link_loss(double prob, std::uint64_t seed);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tier::net
