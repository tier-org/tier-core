#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tier::core {

// A peer's stable network id: 32 bytes = a hash (SHA-256) of its public key.
// Hashing the key, rather than using the key directly, keeps the id fixed-size
// and independent of the signature algorithm (Ed25519 now, larger post-quantum
// keys later).
using PeerId = std::array<std::uint8_t, 32>;

enum class Role : std::uint8_t { client, validator, keeper, transmitter };

// SWIM liveness. Order matters for the merge: alive < suspect < dead, so at an
// equal incarnation a worse report wins.
enum class Liveness : std::uint8_t { alive = 0, suspect = 1, dead = 2 };

struct PeerInfo {
  PeerId id{};
  std::string address;              // "ip:port" to dial; empty if not yet known
  Role role = Role::client;
  std::uint64_t incarnation = 0;    // a peer raises its own to refute suspicion
  Liveness liveness = Liveness::alive;
};

// The known-peers table with SWIM / anti-entropy merge semantics. Transport
// agnostic: the network layer feeds it updates and reads snapshots to gossip.
class Membership {
 public:
  // Merge one received update. Returns true if local state changed.
  // A higher incarnation always wins; at an equal incarnation a worse liveness
  // (dead > suspect > alive) wins; a lower incarnation is ignored.
  bool apply(const PeerInfo& update);

  // Drop an entry (e.g. a dead peer past its cleanup grace). Returns true if an
  // entry was removed.
  bool remove(const PeerId& id);

  [[nodiscard]] std::optional<PeerInfo> find(const PeerId& id) const;
  [[nodiscard]] std::size_t size() const noexcept;

  // All entries, for an anti-entropy push to a peer.
  [[nodiscard]] std::vector<PeerInfo> snapshot() const;

 private:
  std::map<PeerId, PeerInfo> peers_;
};

}  // namespace tier::core
