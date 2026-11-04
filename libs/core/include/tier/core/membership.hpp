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

enum class Role : std::uint8_t {
  client,
  validator,
  keeper,
  transmitter,
  // Reachable infrastructure that serves the presence registry and (M2)
  // hole-punch signaling for client-to-client messaging. See
  // docs/communicator.md.
  communicator
};

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

// Every role bit this version defines a meaning for. Used to interpret the
// known bits of a roles byte; unknown bits (from a newer peer) are preserved
// verbatim and ignored, not rejected - see decode_membership. Update when a
// role is added to the enum.
inline constexpr RoleSet kAllRoles = static_cast<RoleSet>(
    role_bit(Role::client) | role_bit(Role::validator) |
    role_bit(Role::keeper) | role_bit(Role::transmitter) |
    role_bit(Role::communicator));

// Roles that make a node reachable infrastructure (the "backbone"): every role
// except a plain client. A node holding any of these accepts inbound
// connections, advertises a stable address and is a dial target. A node that
// holds only the client role is an edge node: it dials out to infrastructure
// and is reached over the connection it opened, never dialed. This is the
// topology boundary used by autodial - see docs/topology.md.
inline constexpr RoleSet kInfrastructureRoles =
    static_cast<RoleSet>(kAllRoles & ~role_bit(Role::client));

[[nodiscard]] constexpr bool is_infrastructure(RoleSet set) noexcept {
  return (set & kInfrastructureRoles) != 0;
}

// SWIM liveness. Order matters for the merge: alive < suspect < dead, so at an
// equal incarnation a worse report wins.
enum class Liveness : std::uint8_t { alive = 0, suspect = 1, dead = 2 };

struct PeerInfo {
  PeerId id{};
  // The owner's 32-byte Ed25519 public key. The id is SHA-256 of this key, so a
  // record is authentic only if sha256(public_key) == id and `signature` below
  // verifies against this key. All-zero when unknown (a locally built record
  // that has not been sealed yet, or a legacy/unsigned test record).
  std::array<std::uint8_t, 32> public_key{};
  // The owner's signature over its owner-asserted fields (see
  // tier::core::membership_signing_payload). Empty when the record is unsigned.
  // The network layer verifies this before trusting a gossiped record, so a peer
  // cannot forge another peer's roles, version, addresses or incarnation. It is
  // carried through gossip so a relayed record stays verifiable transitively.
  std::vector<std::uint8_t> signature;
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

// Default cap on the number of entries the table holds (A3). Signatures make a
// record authentic but do not bound how many identities a party can mint, so an
// unbounded table is a memory-exhaustion vector: a flood of validly signed junk
// identities would grow it without limit. The cap bounds memory; the eviction
// policy (see apply) keeps the useful records - a node's own, infrastructure
// over clients, alive over dead - when the table is full. Generous relative to a
// real network's backbone, so it never bites a healthy mesh; tunable per node.
inline constexpr std::size_t kDefaultMaxMembershipEntries = 100000;

// The known-peers table with SWIM / anti-entropy merge semantics. Transport
// agnostic: the network layer feeds it updates and reads snapshots to gossip.
class Membership {
 public:
  Membership() = default;
  explicit Membership(std::size_t max_entries) : max_entries_(max_entries) {}

  // Pin an id that must never be evicted to make room (the node's own id). An
  // unpinned least-valuable entry is chosen instead.
  void set_pinned(const PeerId& id) { pinned_ = id; }

  // Merge one received update. Returns true if local state changed.
  // A higher incarnation always wins; at an equal incarnation a worse liveness
  // (dead > suspect > alive) wins; a lower incarnation is ignored. An update for
  // a tombstoned id (see bury) is ignored unless its incarnation is strictly
  // greater than the tombstone's, which lifts the tombstone (a genuine rejoin).
  //
  // Admitting a new id is subject to the table budget (A3): if the table is full
  // (max_entries), the new record is admitted only by evicting the single
  // least-valuable unpinned entry, and only when the new record is strictly more
  // valuable than it (infrastructure outranks client; alive outranks
  // suspect/dead). Otherwise the new id is rejected (apply returns false) and the
  // table stays bounded. Updates to an id already present are never subject to
  // the budget (they do not grow the table).
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
  // Make room for one new id when the table is at capacity: evict the single
  // least-valuable unpinned entry if the incoming record outranks it. Returns
  // true if there is now room to insert (either the table was not full, or an
  // entry was evicted), false if the incoming record should be rejected.
  [[nodiscard]] bool make_room_for(const PeerInfo& incoming);

  std::map<PeerId, PeerInfo> peers_;
  // Buried ids mapped to the incarnation they were buried at. An apply for such
  // an id is suppressed unless it carries a strictly higher incarnation.
  std::map<PeerId, std::uint64_t> tombstones_;
  std::size_t max_entries_ = kDefaultMaxMembershipEntries;
  // The node's own id (optional): never evicted to admit another record.
  std::optional<PeerId> pinned_;
};

}  // namespace tier::core
