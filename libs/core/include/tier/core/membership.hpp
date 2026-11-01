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

// A node may hold several roles at once (e.g. a validator that is also a
// keeper), so roles travel as a bitmask: bit (1 << Role) per role held. This
// keeps the single on-wire role byte and leaves room for future roles.
using RoleSet = std::uint8_t;

[[nodiscard]] constexpr RoleSet role_bit(Role r) noexcept {
  return static_cast<RoleSet>(1U << static_cast<unsigned>(r));
}

[[nodiscard]] constexpr bool has_role(RoleSet set, Role r) noexcept {
  return (set & role_bit(r)) != 0;
}

// Every defined role bit OR'd together; used to reject unknown bits off the
// wire. Update when a role is added to the enum.
inline constexpr RoleSet kAllRoles = static_cast<RoleSet>(
    role_bit(Role::client) | role_bit(Role::validator) |
    role_bit(Role::keeper) | role_bit(Role::transmitter));

// SWIM liveness. Order matters for the merge: alive < suspect < dead, so at an
// equal incarnation a worse report wins.
enum class Liveness : std::uint8_t { alive = 0, suspect = 1, dead = 2 };

struct PeerInfo {
  PeerId id{};
  // Candidate "ip:port" endpoints to dial, one per reachable interface/family
  // (e.g. an IPv4 and an IPv6 address). Empty if none is known yet. A node
  // advertises every address it is reachable at so a dialer can pick one of a
  // family it can use; a peer with a single address behaves as before.
  std::vector<std::string> addresses;
  RoleSet roles = role_bit(Role::client);  // one or more roles this node holds
  // The peer's advertised software version (tier::core::version(), e.g.
  // "0.2.4"). Carried through gossip so the mesh can be inspected for version
  // skew. Empty when unknown: a peer too old to advertise one, or a
  // liveness-only update that omitted it (the known value is then kept).
  std::string version;
  std::uint64_t incarnation = 0;    // a peer raises its own to refute suspicion
  Liveness liveness = Liveness::alive;
};

// The known-peers table with SWIM / anti-entropy merge semantics. Transport
// agnostic: the network layer feeds it updates and reads snapshots to gossip.
class Membership {
 public:
  // Merge one received update. Returns true if local state changed.
  // A higher incarnation always wins; at an equal incarnation a worse liveness
  // (dead > suspect > alive) wins; a lower incarnation is ignored. An update for
  // a tombstoned id (see bury) is ignored unless its incarnation is strictly
  // greater than the tombstone's, which lifts the tombstone (a genuine rejoin).
  bool apply(const PeerInfo& update);

  // Drop an entry (e.g. a dead peer past its cleanup grace). Returns true if an
  // entry was removed.
  bool remove(const PeerId& id);

  // Bury a peer: remove its entry and record a tombstone at `incarnation`, so a
  // stale gossip report about it (at the same or a lower incarnation) cannot
  // re-insert it. Without this, a just-removed peer is resurrected the moment a
  // laggard node gossips it back. A later report at a strictly higher
  // incarnation (a real rejoin) lifts the tombstone and is applied normally.
  void bury(const PeerId& id, std::uint64_t incarnation);

  // Lift a tombstone (its suppression window has elapsed), so the id can be
  // learned fresh again.
  void forget(const PeerId& id);

  [[nodiscard]] bool is_tombstoned(const PeerId& id) const;

  [[nodiscard]] std::optional<PeerInfo> find(const PeerId& id) const;
  [[nodiscard]] std::size_t size() const noexcept;

  // All entries, for an anti-entropy push to a peer.
  [[nodiscard]] std::vector<PeerInfo> snapshot() const;

 private:
  std::map<PeerId, PeerInfo> peers_;
  // Buried ids mapped to the incarnation they were buried at. An apply for such
  // an id is suppressed unless it carries a strictly higher incarnation.
  std::map<PeerId, std::uint64_t> tombstones_;
};

}  // namespace tier::core
