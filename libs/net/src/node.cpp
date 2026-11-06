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

#include <random>

#include "tier/core/control.hpp"
#include "tier/core/version.hpp"
#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/msg/presence.hpp"
#include "tier/net/rendezvous.hpp"

namespace tier::net {
namespace {

// How many distinct peers must agree on our observed address before we adopt
// it. One is enough to bootstrap from a single seed; raising it hardens against
// a lying peer, and belongs with signed membership (not yet in place).
constexpr std::size_t kAddressConfirmations = 1;

// Wall-clock unix seconds. Presence records carry an issue stamp and an expiry
// in wall-clock time (they are relayed and cached across nodes), unlike the
// steady_clock used for local timers.
std::uint64_t unix_now() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// Presence record lifetime and how often an edge client republishes it (well
// before expiry, so a refresh always lands first). Also the per-target budget
// for resolving and the lookup re-issue interval.
constexpr std::uint64_t kPresenceTtlSeconds = 300;
constexpr auto kPresenceRegisterInterval = std::chrono::seconds(120);
constexpr auto kPendingSendTimeout = std::chrono::seconds(20);
constexpr auto kLookupRetryInterval = std::chrono::seconds(2);

// User-directory enrollment lifetime and republish cadence, and how long a
// self-issued device credential is valid. The credential is long-lived (the
// device holds the user key in the single-process case and re-issues on
// restart); the directory enrollment is short like presence so it ages out.
constexpr std::uint64_t kUserEnrollTtlSeconds = 300;
constexpr auto kUserRegisterInterval = std::chrono::seconds(120);
constexpr std::uint64_t kDeviceCredentialTtlSeconds = 365ULL * 24 * 3600;

// Application-message kind, the first byte of the sealed transport plaintext.
// A node message is device-to-device with no user layer (unchanged behavior); a
// user message carries a user envelope (sender user, recipient user, inner).
// This framing is internal to the node: callers see only the inner payload.
constexpr tier::crypto::Byte kAppKindNode = 0x00;
constexpr tier::crypto::Byte kAppKindUser = 0x01;

// Hole punch: how long to let a direct dial try before escalating to a
// coordinated punch, and how often to re-issue a punch request while a target
// stays unconnected (see docs/communicator.md, M-NAT).
constexpr auto kPunchGrace = std::chrono::seconds(3);
constexpr auto kPunchRetryInterval = std::chrono::seconds(3);

// Minimum gap between dial attempts to the same address.
constexpr auto kDialRetry = std::chrono::seconds(2);

// Bounded backbone degree (docs/topology.md, Phase 2). A backbone node holds a
// connection to its ring neighbors - this many in total (half successors, half
// predecessors by id), even rather than odd so the neighbor relation is
// symmetric. When the backbone is this small or smaller the window covers
// everyone and the graph is a full mesh, matching the pre-Phase-2 behavior.
constexpr std::size_t kBackboneDegree = 8;

// How many backbone entry points an edge (client) node dials for redundancy.
constexpr std::size_t kClientFanout = 3;

// How long a demotion (an infrastructure role dropping to plain client) keeps
// being gossiped network-wide (docs/topology.md, A6). The scoping filter would
// otherwise stop forwarding the record the moment it becomes a client, so the
// revocation would reach only the owner's immediate neighbor. Holding it in
// anti-entropy for a window comfortably larger than convergence (full sync runs
// every second) lets the demotion reach every node and heals a dropped rumor.
// Assumes a node is not partitioned away for longer than this window across a
// role downgrade; a longer outage falls back to the record going client-local.
constexpr auto kDemotionGossipWindow = std::chrono::seconds(30);

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

// Seed a node's own incarnation from the wall clock (microseconds since the
// epoch) rather than a fixed 1, so a restarted node always re-enters the mesh
// with an incarnation above any record a peer still remembers from a previous
// run. Its fresh record (new role, version, addresses) then supersedes the
// stale one by the normal merge rule - crucial when the stale record is a
// scoped-out edge (client) record that would never be gossiped back for the
// owner to refute (docs/topology.md). Assumes the clock does not move backward
// across a restart (NTP-synced hosts); microsecond resolution makes a
// same-tick restart effectively impossible, and reconcile_self remains the
// fallback if a stale record ever still outranks us.
std::uint64_t startup_incarnation() {
  const auto since_epoch =
      std::chrono::system_clock::now().time_since_epoch();
  const auto micros =
      std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count();
  return micros > 0 ? static_cast<std::uint64_t>(micros) : 1;
}

}  // namespace

Node::Node(tier::crypto::NodeIdentity identity, tier::core::RoleSet roles,
           const std::string& ip, std::uint16_t port,
           tier::core::SwimConfig swim, std::string network,
           tier::core::VersionRange version_range)
    : identity_(std::move(identity)),
      self_id_(tier::crypto::sha256(identity_.public_key())),
      roles_(roles),
      network_(std::move(network)),
      endpoint_(identity_, ip, port, network_),
      rng_(std::random_device{}()),
      version_range_(std::move(version_range)),
      fd_(self_id_, membership_, swim,
          [this](const tier::core::PeerId& to,
                 const std::vector<std::uint8_t>& msg) {
            const auto it = conn_by_peer_.find(to);
            if (it != conn_by_peer_.end()) {
              endpoint_.send(it->second, msg);
            }
          }) {
  self_address_ = ip + ":" + std::to_string(endpoint_.local_port());

  // Our own record must never be evicted when the table is full (A3 budget).
  membership_.set_pinned(self_id_);

  tier::core::PeerInfo me;
  me.id = self_id_;
  // Advertise a bind address only if it is concrete. On a wildcard bind ("::"
  // or "0.0.0.0") self_address_ is not a reachable address, so start with an
  // empty set and adopt the real one once a peer reports it (handle_observed).
  if (is_dialable(self_address_)) {
    me.addresses = {self_address_};
  }
  me.roles = roles;
  me.version = std::string(tier::core::version());
  me.incarnation = startup_incarnation();
  me.liveness = tier::core::Liveness::alive;
  seal_self(me);
  membership_.apply(me);

  // The failure detector refutes a suspicion of ourselves by raising our own
  // incarnation; that changes an owner-signed field, so it must re-seal the
  // record. Hand it a sealer rather than teach core about crypto.
  fd_.set_self_sealer([this](const tier::core::PeerInfo& p) {
    tier::core::PeerInfo sealed = p;
    // Roles and version are locally authoritative: re-stamp them so a refutation
    // can never re-sign a role a stale gossiped record briefly put on us.
    sealed.roles = roles_;
    sealed.version = std::string(tier::core::version());
    seal_self(sealed);
    return sealed;
  });

  endpoint_.on_handshake([this](ConnId conn, bool, const PeerId&) {
    push_membership(conn);
    // Tell the peer where we see it: it binds a wildcard and otherwise cannot
    // learn its own reachable address.
    if (const auto addr = endpoint_.remote_address(conn)) {
      endpoint_.send(conn, tier::core::encode_observed_addr(*addr));
    }
    // Announce our encryption keys so the peer can send us sealed messages.
    endpoint_.send(conn, tier::msg::make_enc_keys_announce(identity_, network_));
  });
  endpoint_.on_message([this](ConnId conn, const PeerId& key,
                              std::span<const tier::crypto::Byte> payload) {
    const tier::core::PeerId from = tier::crypto::sha256(key);
    const auto ctype = tier::core::peek_control_type(payload);
    if (ctype == tier::core::ControlType::observed_addr) {
      handle_observed(from, payload);
      return;
    }
    if (ctype == tier::core::ControlType::enc_keys) {
      handle_enc_keys(from, key, payload);
      return;
    }
    if (ctype == tier::core::ControlType::app_sealed) {
      handle_sealed(key, payload);
      return;
    }
    if (ctype == tier::core::ControlType::presence_register) {
      handle_presence_register(payload, unix_now());
      return;
    }
    if (ctype == tier::core::ControlType::presence_lookup) {
      handle_presence_lookup(conn, payload, unix_now());
      return;
    }
    if (ctype == tier::core::ControlType::presence_result) {
      handle_presence_result(payload, std::chrono::steady_clock::now());
      return;
    }
    if (ctype == tier::core::ControlType::user_register) {
      handle_user_register(from, payload, unix_now());
      return;
    }
    if (ctype == tier::core::ControlType::user_lookup) {
      handle_user_lookup(conn, payload, unix_now());
      return;
    }
    if (ctype == tier::core::ControlType::user_result) {
      handle_user_result(payload, std::chrono::steady_clock::now());
      return;
    }
    if (ctype == tier::core::ControlType::hole_punch_request) {
      handle_hole_punch_request(conn, from, payload);
      return;
    }
    if (ctype == tier::core::ControlType::hole_punch_signal) {
      handle_hole_punch_signal(conn, payload, std::chrono::steady_clock::now());
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

const std::string& Node::network() const noexcept { return network_; }

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
  // Keep the seed list for re-dialing: autodial only walks the membership, so a
  // seed that never completed a handshake leaves no entry to retry from. The
  // backoff clock starts after this first attempt (retry_seeds grows it).
  seeds_ = seeds;
  for (const std::string& addr : seeds_) {
    if (is_dialable(addr)) {
      seed_retry_[addr];  // default: next=now-epoch (eligible), attempts=0
    }
  }
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
    if (self.has_value()) {
      // Guarded by has_value() above; the checker loses the guard across the
      // loop's earlier continue branches, so suppress its false positive here.
      const auto& self_addrs =
          self->addresses;  // NOLINT(bugprone-unchecked-optional-access)
      if (std::find(self_addrs.begin(), self_addrs.end(), addr) !=
          self_addrs.end()) {
        continue;
      }
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
    // First attempt made: arm the seed retry clock so retry_seeds waits a
    // backoff before trying this seed again.
    if (const auto it = seed_retry_.find(addr); it != seed_retry_.end()) {
      it->second.attempts = 1;
      it->second.next = now + std::chrono::seconds(1);
    }
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

  // Client-to-client discovery (docs/communicator.md): publish our presence (if
  // an edge client), drive queued sends toward resolution/flush, and age out
  // expired registry entries (a no-op unless we are a communicator).
  const std::uint64_t unow = unix_now();
  register_presence(now, unow);
  service_pending_sends(now);
  presence_registry_.prune(unow);
  // Multi-identity (docs/multi-identity.md): publish our user enrollment, drive
  // queued user-level sends, and age out the user directory (a no-op unless we
  // are a communicator).
  register_user(now, unow);
  service_user_sends(now);
  user_directory_.prune(unow);

  // Expire demotion-propagation windows: once elapsed, a demoted peer's client
  // record falls back to local scope like any other client (docs/topology.md,
  // A6). By now the network has converged on the demotion.
  for (auto it = demoted_until_.begin(); it != demoted_until_.end();) {
    if (now >= it->second) {
      it = demoted_until_.erase(it);
    } else {
      ++it;
    }
  }

  // Dissemination (docs/topology.md, Phase 3b). Timely propagation is driven by
  // rumor-push: records changed during this poll (new peers, incarnation bumps,
  // liveness and address changes the detector or merge produced) are flushed now
  // as one small message to every neighbor. Each node forwards a given version
  // once (apply() reports only genuinely newer records), so a change floods the
  // backbone in O(log N) rounds without resending the whole table every tick.
  if (!rumor_queue_.empty()) {
    for (const auto& msg :
         tier::core::encode_membership_messages(rumor_queue_)) {
      endpoint_.broadcast(msg);
    }
    rumor_queue_.clear();
  }

  // Periodic full anti-entropy: the infrequent backstop that heals anything a
  // rumor missed (a dropped frame, a peer that joined mid-flood). Only the
  // propagated (backbone + self) records are sent; edge-client records stay
  // local to the backbone they attach to. A snapshot too large for one frame is
  // split into several self-contained messages.
  constexpr auto kFullSyncInterval = std::chrono::seconds(1);
  if (now - last_full_sync_ >= kFullSyncInterval) {
    for (const auto& msg :
         tier::core::encode_membership_messages(gossip_records())) {
      endpoint_.broadcast(msg);
    }
    last_full_sync_ = now;
  }
}

void Node::push_membership(ConnId conn) {
  // Initial sync to a freshly connected peer: the propagated (backbone + self)
  // records, so a joiner converges immediately without waiting for the periodic
  // anti-entropy.
  for (const auto& msg :
       tier::core::encode_membership_messages(gossip_records())) {
    endpoint_.send(conn, msg);
  }
}

bool Node::should_propagate(const tier::core::PeerInfo& p) const noexcept {
  return tier::core::is_infrastructure(p.roles) || p.id == self_id_;
}

std::vector<tier::core::PeerInfo> Node::gossip_records() const {
  std::vector<tier::core::PeerInfo> out;
  const auto now = std::chrono::steady_clock::now();
  for (const auto& p : membership_.snapshot()) {
    // Propagate by role (backbone + self), plus any record inside its
    // demotion-propagation window so a just-revoked infrastructure status
    // reaches the whole network, not only the owner's neighbor (A6).
    if (should_propagate(p) || demotion_active(p.id, now)) {
      out.push_back(p);
    }
  }
  return out;
}

void Node::queue_rumor(const tier::core::PeerInfo& p) {
  if (should_propagate(p)) {
    rumor_queue_.push_back(p);
  }
}

bool Node::demotion_active(
    const tier::core::PeerId& id,
    std::chrono::steady_clock::time_point now) const {
  const auto it = demoted_until_.find(id);
  return it != demoted_until_.end() && now < it->second;
}

void Node::merge_message(std::span<const tier::crypto::Byte> payload) {
  const auto decoded = tier::core::decode_membership_message(payload);
  if (!decoded) {
    return;
  }
  for (const tier::core::PeerInfo& peer : *decoded) {
    // Authenticity first: a record is trusted only if it carries the owner's
    // public key (hashing to its id) and a valid signature over the owner's
    // fields for this network. This is the security boundary - a peer that
    // relays membership cannot forge another peer's roles, version, addresses or
    // incarnation, including the receiver's own record. An unverifiable record
    // is dropped, never merged.
    if (!verify_owner(peer)) {
      continue;
    }
    // Our own record is never merged from gossip: a relayed copy (necessarily
    // signed by this key, since verify_owner dropped any forgery) may be stale -
    // an old role or incarnation from before a restart. Reconcile it against our
    // authoritative local state instead.
    if (peer.id == self_id_) {
      reconcile_self(peer);
      continue;
    }
    // Network version policy: do not admit a peer whose advertised version is
    // outside this network's window (an unconstrained range admits all; an
    // unknown/old version is admitted leniently). This gates membership only;
    // it is cooperative governance, not a security boundary.
    if (!tier::core::version_admitted(version_range_, peer.version)) {
      continue;
    }
    // Capture the prior record before applying, so a role transition can be
    // detected: a peer dropping from an infrastructure role to plain client is
    // a demotion whose propagation the scoping filter would otherwise suppress.
    const auto prev = membership_.find(peer.id);
    if (membership_.apply(peer)) {
      const bool was_infra =
          prev.has_value() && tier::core::is_infrastructure(prev->roles);
      const bool now_infra = tier::core::is_infrastructure(peer.roles);
      if (was_infra && !now_infra) {
        // Demotion (A6): the new record is a client and would not be gossiped by
        // role, but the revocation of the peer's former backbone status must
        // reach the whole network. Force this one forward and keep it in
        // anti-entropy for a bounded window (see gossip_records / demotion_active
        // and kDemotionGossipWindow).
        demoted_until_[peer.id] =
            std::chrono::steady_clock::now() + kDemotionGossipWindow;
        rumor_queue_.push_back(peer);
      } else {
        queue_rumor(peer);  // novel/newer: forward it once to our neighbors
      }
      if (on_change_) {
        on_change_(peer);
      }
    } else {
      // apply() rejected the incoming record as not newer than what we hold. If
      // we actually hold a strictly newer record for this id, push ours back so
      // the sender (and, via rumor, the rest of the network) converges onto it.
      // This is what carries a demotion's revocation to a node that never
      // witnessed the infrastructure->client transition (A6 remainder): a node
      // that learned the fresh client record first, then receives a stale
      // infrastructure announcement, re-gossips the client record instead of
      // silently dropping the stale one and leaving the sender to keep dialing a
      // now-demoted peer as backbone.
      const auto cur = membership_.find(peer.id);
      if (cur && cur->incarnation > peer.incarnation) {
        const bool peer_infra = tier::core::is_infrastructure(peer.roles);
        const bool cur_infra = tier::core::is_infrastructure(cur->roles);
        if (peer_infra && !cur_infra) {
          // The stale record still asserts the backbone status our newer record
          // revokes: propagate the revocation network-wide for the demotion
          // window, exactly as the node that witnessed the transition does.
          demoted_until_[peer.id] =
              std::chrono::steady_clock::now() + kDemotionGossipWindow;
          rumor_queue_.push_back(*cur);
        } else {
          // Otherwise ours propagates by the normal scoping rule (a backbone
          // record is re-gossiped; a client record stays local, which is fine -
          // a client is only ever held by the backbone it attaches to).
          queue_rumor(*cur);
        }
      }
    }
  }
}

void Node::reconcile_self(const tier::core::PeerInfo& relayed) {
  const auto self = membership_.find(self_id_);
  if (!self) {
    return;  // self is seeded at construction and never removed
  }
  // Can the relayed record win over ours anywhere it is gossiped? Only if its
  // incarnation is at least ours. And does it actually disagree with what we
  // authoritatively assert? A plain echo of our current record (same fields,
  // same incarnation, alive) must not trigger a refutation, or every gossip
  // round would ratchet our incarnation upward forever.
  const bool could_supersede = relayed.incarnation >= self->incarnation;
  const bool differs = relayed.roles != roles_ ||
                       relayed.version != tier::core::version() ||
                       relayed.addresses != self->addresses ||
                       relayed.incarnation != self->incarnation ||
                       relayed.liveness != tier::core::Liveness::alive;
  if (!could_supersede || !differs) {
    return;
  }
  // Refute: re-assert our authoritative record at an incarnation above the stale
  // one. Roles and version come from local config, addresses from what we have
  // learned so far (observed_addr re-confirms them); the relayed record dictates
  // none of it.
  tier::core::PeerInfo me = *self;
  me.roles = roles_;
  me.version = std::string(tier::core::version());
  me.liveness = tier::core::Liveness::alive;
  // Saturate at the ceiling rather than wrap to zero (which would lose to the
  // stale record); unreachable in practice, defined at the edge.
  me.incarnation =
      relayed.incarnation == UINT64_MAX ? UINT64_MAX : relayed.incarnation + 1;
  seal_self(me);
  if (membership_.apply(me)) {
    queue_rumor(me);
    if (on_change_) {
      on_change_(me);
    }
  }
}

void Node::seal_self(tier::core::PeerInfo& me) const {
  const auto& pk = identity_.public_key();
  std::copy(pk.begin(), pk.end(), me.public_key.begin());
  me.signature =
      identity_.signer().sign(tier::core::membership_signing_payload(network_, me));
}

bool Node::verify_owner(const tier::core::PeerInfo& p) const {
  // The id must be the hash of the key the record carries, or the key is not
  // the owner's and the signature below would be meaningless.
  const tier::core::PeerId derived = tier::crypto::sha256(p.public_key);
  if (derived != p.id) {
    return false;
  }
  const tier::crypto::Ed25519Verifier verifier(p.public_key);
  const auto payload = tier::core::membership_signing_payload(network_, p);
  return verifier.verify(payload, p.signature);
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

std::vector<tier::core::PeerId> Node::ring_dial_targets(
    const std::vector<tier::core::PeerId>& sorted_backbone,
    const tier::core::PeerId& self, bool self_is_backbone,
    std::size_t k_backbone, std::size_t k_client) {
  std::vector<tier::core::PeerId> out;
  const std::size_t n = sorted_backbone.size();
  if (n == 0) {
    return out;
  }
  // Insertion index of self on the sorted ring (also self's own index when it is
  // a backbone member).
  const std::size_t p = static_cast<std::size_t>(
      std::lower_bound(sorted_backbone.begin(), sorted_backbone.end(), self) -
      sorted_backbone.begin());

  if (self_is_backbone) {
    // self must be present; if not, nothing to anchor on.
    if (p >= n || !(sorted_backbone[p] == self)) {
      return out;
    }
    // The half-successors and half-predecessors by circular index. With n-1
    // others and a window of up to k_backbone, this covers everyone (full mesh)
    // once the backbone is small.
    const std::size_t half = k_backbone / 2;
    std::vector<std::size_t> idx;
    for (std::size_t j = 1; j <= half && idx.size() < n - 1; ++j) {
      idx.push_back((p + j) % n);          // successor
      if (idx.size() < n - 1) {
        idx.push_back((p + n - j) % n);    // predecessor
      }
    }
    std::set<std::size_t> uniq(idx.begin(), idx.end());
    uniq.erase(p);
    for (const std::size_t i : uniq) {
      out.push_back(sorted_backbone[i]);
    }
  } else {
    // Edge node: self is not a backbone member. Take the k_client id-successors
    // (wrapping) as a small, stable, redundant set of entry points. The edge
    // always initiates toward backbone, so no symmetry is required.
    const std::size_t take = std::min(k_client, n);
    std::set<std::size_t> uniq;
    for (std::size_t j = 0; j < take; ++j) {
      uniq.insert((p + j) % n);
    }
    for (const std::size_t i : uniq) {
      out.push_back(sorted_backbone[i]);
    }
  }
  return out;
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
  me.roles = roles_;  // roles and version are locally authoritative, never
  me.version = std::string(tier::core::version());  // taken from a merged record
  seal_self(me);  // addresses and incarnation changed: re-sign
  if (membership_.apply(me)) {
    queue_rumor(me);
    if (on_change_) {
      on_change_(me);
    }
  }
}

void Node::handle_enc_keys(const tier::core::PeerId& from, const PeerId& sender_key,
                           std::span<const tier::crypto::Byte> payload) {
  auto keys = tier::msg::open_enc_keys_announce(network_, sender_key, payload);
  if (!keys) {
    return;  // malformed or signature did not verify: not this peer's keys
  }
  peer_enc_keys_[from] = *keys;
}

void Node::handle_sealed(const PeerId& sender_key,
                         std::span<const tier::crypto::Byte> payload) {
  auto opened = tier::msg::open(identity_, network_, sender_key, payload);
  if (!opened) {
    return;  // not for us, forged, or undecryptable: drop silently
  }
  // The first byte of the plaintext is the application-message kind (see
  // kAppKindNode/kAppKindUser). An empty or unknown-kind message is dropped.
  if (opened->plaintext.empty()) {
    return;
  }
  const tier::crypto::Byte kind = opened->plaintext.front();
  const tier::crypto::ByteSpan body(opened->plaintext.data() + 1,
                                    opened->plaintext.size() - 1);

  ReceivedMessage rx;
  rx.sender = opened->sender_id;
  rx.suite = opened->suite;

  if (kind == kAppKindNode) {
    // Plain device-to-device message: no user layer.
    rx.plaintext.assign(body.begin(), body.end());
  } else if (kind == kAppKindUser) {
    // User message: authenticate the sender user and route to the addressed
    // local user. Drop a forged envelope or one not addressed to a user we host.
    auto u = tier::msg::open_user_envelope(network_, rx.sender, unix_now(), body);
    if (!u) {
      return;
    }
    if (users_.find(u->recipient_user_id) == users_.end()) {
      return;  // not addressed to any user hosted here
    }
    rx.sender_user = u->sender_user_id;
    rx.recipient_user = u->recipient_user_id;
    rx.plaintext = std::move(u->plaintext);
  } else {
    return;  // unknown kind
  }

  if (on_message_received_) {
    on_message_received_(rx);
  }
  // Only plain node (device-to-device) messages are buffered for `tierctl
  // inbox`. A user message is not stored on the node: it is emitted via the
  // callback to the application layer, which delivers it to a live subscriber
  // or drops it (online-only - see docs/app-protocol.md).
  if (kind == kAppKindNode) {
    inbox_.push_back(std::move(rx));
  }
}

std::vector<tier::core::PeerId> Node::live_communicators() const {
  std::vector<tier::core::PeerId> out;
  for (const tier::core::PeerInfo& p : membership_.snapshot()) {
    if (tier::core::has_role(p.roles, tier::core::Role::communicator) &&
        p.liveness != tier::core::Liveness::dead) {
      out.push_back(p.id);
    }
  }
  return out;
}

void Node::dial_addresses(const std::vector<std::string>& addresses,
                          std::chrono::steady_clock::time_point now) {
  const auto chosen = select_dial_candidate(addresses, dialed_, now, kDialRetry);
  if (!chosen) {
    return;
  }
  const auto hp = split_host_port(*chosen);
  if (!hp) {
    return;
  }
  dialed_[*chosen] = now;
  try {
    endpoint_.connect(hp->first, hp->second);
  } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
    // A malformed or unroutable address must not take us down; the dialed_
    // rate-limit keeps us from retrying it in a tight loop.
  }
}

void Node::handle_presence_register(std::span<const tier::crypto::Byte> payload,
                                    std::uint64_t now_unix) {
  // Only a communicator keeps a registry; others ignore registrations.
  if (!tier::core::has_role(roles_, tier::core::Role::communicator)) {
    return;
  }
  const auto rec = tier::msg::open_presence_register(network_, payload);
  if (!rec) {
    return;  // malformed or signature did not verify
  }
  presence_registry_.store(rec->id, rec->record_bytes, rec->issued_unix,
                           rec->expiry_unix, now_unix);
}

void Node::handle_presence_lookup(ConnId conn,
                                  std::span<const tier::crypto::Byte> payload,
                                  std::uint64_t now_unix) {
  if (!tier::core::has_role(roles_, tier::core::Role::communicator)) {
    return;
  }
  const auto target = tier::msg::open_presence_lookup(payload);
  if (!target) {
    return;
  }
  const auto found = presence_registry_.lookup(*target, now_unix);
  const tier::crypto::ByteSpan bytes =
      found ? tier::crypto::ByteSpan(found->data(), found->size())
            : tier::crypto::ByteSpan();
  endpoint_.send(conn, tier::msg::make_presence_result(*target, bytes));
}

void Node::handle_presence_result(std::span<const tier::crypto::Byte> payload,
                                  std::chrono::steady_clock::time_point now) {
  // We only trust a result for a target we actually have pending work for, and
  // we re-verify the record ourselves (never on the communicator's word).
  tier::core::PeerId target{};
  bool matched = false;
  for (const auto& [id, queue] : pending_sends_) {
    const auto out = tier::msg::open_presence_result(network_, id, payload);
    if (out.has_value()) {
      target = id;
      matched = true;
      if (out->has_value()) {
        peer_enc_keys_[id] = (*out)->enc_keys;
        resolved_addrs_[id] = (*out)->addresses;
      }
      break;
    }
  }
  if (!matched) {
    return;  // not a result for anything we are resolving
  }
  // Dial the resolved peer directly so the queued message can flush once the
  // handshake completes.
  const auto addrs = resolved_addrs_.find(target);
  if (addrs != resolved_addrs_.end() && conn_by_peer_.count(target) == 0) {
    dial_addresses(addrs->second, now);
    // Start the clock on escalating to a hole punch if the direct dial does not
    // connect (the peer may be behind a NAT that drops our unsolicited dial).
    punch_grace_.try_emplace(target, now + kPunchGrace);
  }
}

void Node::register_presence(std::chrono::steady_clock::time_point now,
                             std::uint64_t now_unix) {
  // Only edge clients publish presence; infrastructure is already reachable and
  // gossiped.
  if (tier::core::is_infrastructure(roles_)) {
    return;
  }
  if (now < next_presence_register_) {
    return;
  }

  const auto comms = live_communicators();
  if (comms.empty()) {
    return;  // no communicator known yet; try again next tick
  }
  const auto self = membership_.find(self_id_);
  if (!self || self->addresses.empty()) {
    return;  // no reachable address to advertise yet
  }

  const std::vector<tier::crypto::Byte> frame = tier::msg::make_presence_register(
      identity_, network_, roles_, self->addresses, now_unix,
      now_unix + kPresenceTtlSeconds);

  const auto responsible =
      responsible_communicators(self_id_, comms, kPresenceReplicas);
  for (const auto& c : responsible) {
    const auto conn = conn_by_peer_.find(c);
    if (conn != conn_by_peer_.end()) {
      endpoint_.send(conn->second, frame);
    } else if (const auto info = membership_.find(c); info) {
      dial_addresses(info->addresses, now);  // connect so we can register next tick
    }
  }
  next_presence_register_ = now + kPresenceRegisterInterval;
}

void Node::service_pending_sends(std::chrono::steady_clock::time_point now) {
  for (auto it = pending_sends_.begin(); it != pending_sends_.end();) {
    const tier::core::PeerId& to = it->first;
    auto& queue = it->second;

    // Flush anything deliverable now (connected + keys known).
    if (conn_by_peer_.count(to) != 0 && peer_enc_keys_.count(to) != 0) {
      for (const auto& m : queue) {
        deliver_sealed(to, m.suite, tier::crypto::ByteSpan(m.plaintext.data(),
                                                           m.plaintext.size()));
      }
      queue.clear();
    }

    // Drop timed-out messages.
    queue.erase(std::remove_if(queue.begin(), queue.end(),
                               [&](const PendingSend& m) {
                                 return now >= m.deadline;
                               }),
                queue.end());

    if (queue.empty()) {
      lookup_sent_.erase(to);
      resolved_addrs_.erase(to);
      punch_grace_.erase(to);
      punch_sent_.erase(to);
      it = pending_sends_.erase(it);
      continue;
    }

    // Still pending: drive resolution. If we already resolved addresses, keep
    // dialing the peer directly; otherwise ask a responsible communicator.
    if (const auto addrs = resolved_addrs_.find(to);
        addrs != resolved_addrs_.end() && conn_by_peer_.count(to) == 0) {
      dial_addresses(addrs->second, now);
      // If the direct dial has not connected within the grace window, the peer
      // may be behind a NAT; escalate to a coordinated hole punch (rate-limited).
      const auto grace = punch_grace_.find(to);
      if (grace != punch_grace_.end() && now >= grace->second) {
        const auto last = punch_sent_.find(to);
        if (last == punch_sent_.end() || now - last->second >= kPunchRetryInterval) {
          initiate_hole_punch(to, now);
        }
      }
    } else if (peer_enc_keys_.count(to) == 0) {
      const auto last = lookup_sent_.find(to);
      if (last == lookup_sent_.end() || now - last->second >= kLookupRetryInterval) {
        const auto comms = live_communicators();
        const auto responsible =
            responsible_communicators(to, comms, kPresenceReplicas);
        bool asked = false;
        for (const auto& c : responsible) {
          const auto conn = conn_by_peer_.find(c);
          if (conn != conn_by_peer_.end()) {
            endpoint_.send(conn->second, tier::msg::make_presence_lookup(to));
            asked = true;
          } else if (const auto info = membership_.find(c); info) {
            dial_addresses(info->addresses, now);  // connect to ask next tick
          }
        }
        if (asked) {
          lookup_sent_[to] = now;
        }
      }
    }
    ++it;
  }
}

tier::core::PeerId Node::add_user(tier::crypto::NodeIdentity user) {
  const tier::core::PeerId uid = tier::msg::user_id_of(user.public_key());
  // Self-issue this device's credential under the user key held here. Every user
  // envelope sent on behalf of this user carries it. Build it before moving the
  // identity into the record (LocalUser holds a non-default-constructible key).
  std::vector<tier::crypto::Byte> cred = tier::msg::make_device_credential(
      user, network_, self_id_, unix_now() + kDeviceCredentialTtlSeconds);
  LocalUser lu{std::move(user), std::move(cred),
               std::chrono::steady_clock::time_point{}};
  users_.insert_or_assign(uid, std::move(lu));
  return uid;
}

bool Node::remove_user(const tier::core::PeerId& user_id) {
  return users_.erase(user_id) > 0;
}

std::vector<tier::core::PeerId> Node::user_ids() const {
  std::vector<tier::core::PeerId> out;
  out.reserve(users_.size());
  for (const auto& [uid, lu] : users_) {
    out.push_back(uid);
  }
  return out;
}

bool Node::has_user(const tier::core::PeerId& user_id) const {
  return users_.find(user_id) != users_.end();
}

void Node::set_simulated_restricted_nat(bool on) {
  endpoint_.set_simulated_restricted_nat(on);
}

std::vector<std::string> Node::self_candidates() const {
  if (const auto self = membership_.find(self_id_); self) {
    return self->addresses;
  }
  return {};
}

void Node::handle_hole_punch_request(ConnId conn, const tier::core::PeerId& from,
                                     std::span<const tier::crypto::Byte> payload) {
  // Only a communicator relays punches.
  if (!tier::core::has_role(roles_, tier::core::Role::communicator)) {
    return;
  }
  const auto req = tier::msg::open_hole_punch_request(payload);
  if (!req) {
    return;
  }
  // Relay to the target as a signal naming the originator (read from the
  // connection, so it cannot be spoofed). If the target is not connected here,
  // the punch simply cannot be coordinated and is dropped.
  const auto target_conn = conn_by_peer_.find(req->target);
  if (target_conn == conn_by_peer_.end()) {
    return;
  }
  (void)conn;  // the originator's connection; the origin id is `from`
  endpoint_.send(target_conn->second,
                 tier::msg::make_hole_punch_signal(from, req->phase, req->addresses));
}

void Node::handle_hole_punch_signal(ConnId conn,
                                    std::span<const tier::crypto::Byte> payload,
                                    std::chrono::steady_clock::time_point now) {
  const auto sig = tier::msg::open_hole_punch_signal(payload);
  if (!sig) {
    return;
  }
  // Dial the origin's candidates now: our outbound opens our NAT for it, and it
  // is doing the same toward us, so the handshake gets through.
  dial_addresses(sig->addresses, now);
  // On an initiate, reply through the same communicator so the origin dials our
  // candidates too. A respond is terminal (no reply), so there is no ping-pong.
  if (sig->phase == tier::msg::PunchPhase::initiate) {
    endpoint_.send(conn, tier::msg::make_hole_punch_request(
                             sig->origin, tier::msg::PunchPhase::respond,
                             self_candidates()));
  }
}

void Node::initiate_hole_punch(const tier::core::PeerId& target,
                               std::chrono::steady_clock::time_point now) {
  const auto candidates = self_candidates();
  if (candidates.empty()) {
    return;  // we have no reachable address to offer yet
  }
  const auto comms = live_communicators();
  const auto responsible = responsible_communicators(target, comms, kPresenceReplicas);
  for (const auto& c : responsible) {
    const auto conn = conn_by_peer_.find(c);
    if (conn != conn_by_peer_.end()) {
      endpoint_.send(conn->second,
                     tier::msg::make_hole_punch_request(
                         target, tier::msg::PunchPhase::initiate, candidates));
    }
  }
  punch_sent_[target] = now;
}

void Node::handle_user_register(const tier::core::PeerId& from_device,
                                std::span<const tier::crypto::Byte> payload,
                                std::uint64_t now_unix) {
  if (!tier::core::has_role(roles_, tier::core::Role::communicator)) {
    return;
  }
  const auto reg = tier::msg::open_user_register(payload);
  if (!reg) {
    return;
  }
  // The credential must authorize exactly the device on the other end of this
  // connection, so an enrollment cannot claim a device it does not control.
  if (!tier::msg::verify_device_credential(
          network_, reg->user_pub, from_device, now_unix,
          tier::crypto::ByteSpan(reg->credential.data(), reg->credential.size()))) {
    return;
  }
  // Cap the directory TTL so a device cannot pin an entry indefinitely.
  const std::uint64_t expiry =
      std::min(reg->expiry_unix, now_unix + kUserEnrollTtlSeconds);
  user_directory_.enroll(tier::msg::user_id_of(reg->user_pub), from_device,
                         reg->issued_unix, expiry, now_unix);
}

void Node::handle_user_lookup(ConnId conn,
                              std::span<const tier::crypto::Byte> payload,
                              std::uint64_t now_unix) {
  if (!tier::core::has_role(roles_, tier::core::Role::communicator)) {
    return;
  }
  const auto user = tier::msg::open_user_lookup(payload);
  if (!user) {
    return;
  }
  const auto devices = user_directory_.lookup(*user, now_unix);
  endpoint_.send(conn, tier::msg::make_user_result(*user, devices));
}

void Node::handle_user_result(std::span<const tier::crypto::Byte> payload,
                              std::chrono::steady_clock::time_point /*now*/) {
  if (users_.empty()) {
    return;  // nothing to send on behalf of
  }
  // Match the result to a user we are resolving.
  tier::core::PeerId user{};
  std::vector<tier::core::PeerId> devices;
  bool matched = false;
  for (const auto& [u, queue] : pending_user_sends_) {
    const auto res = tier::msg::open_user_result(u, payload);
    if (res) {
      user = u;
      devices = res->device_ids;
      matched = true;
      break;
    }
  }
  if (!matched || devices.empty()) {
    return;  // keep the queued message pending (retry/time out) if no devices yet
  }

  const auto it = pending_user_sends_.find(user);
  if (it == pending_user_sends_.end()) {
    return;
  }
  // Fan each queued message out to every returned device not yet delivered to,
  // as a node-level send carrying a user envelope (send_framed resolves /
  // connects on demand). The device set is resolved repeatedly rather than once:
  // a user's devices enroll asynchronously, and a lookup can be answered (even
  // from a replica) before a device has registered, so a single result may list
  // only some devices. We therefore do NOT erase the pending send here - each new
  // device seen on a later result is delivered to once (deduplicated by
  // m.delivered), and service_user_sends drops the message when its deadline
  // passes. A device hosted on this same node (self) is skipped: that copy was
  // delivered synchronously by send_as_user (loopback).
  for (auto& m : it->second) {
    const auto from = users_.find(m.from_user);
    if (from == users_.end()) {
      continue;  // the sending user was removed since this was queued
    }
    for (const auto& device : devices) {
      if (device == self_id_) {
        continue;  // local recipient already delivered by loopback
      }
      if (!m.delivered.insert(device).second) {
        continue;  // already fanned out to this device
      }
      const std::vector<tier::crypto::Byte> envelope = tier::msg::make_user_envelope(
          from->second.identity.public_key(),
          tier::crypto::ByteSpan(from->second.device_credential.data(),
                                 from->second.device_credential.size()),
          user,  // recipient user id (the directory key we resolved)
          tier::crypto::ByteSpan(m.plaintext.data(), m.plaintext.size()));
      std::vector<tier::crypto::Byte> framed;
      framed.reserve(envelope.size() + 1);
      framed.push_back(kAppKindUser);
      framed.insert(framed.end(), envelope.begin(), envelope.end());
      (void)send_framed(device, m.suite, std::move(framed));
    }
  }
}

void Node::register_user(std::chrono::steady_clock::time_point now,
                         std::uint64_t now_unix) {
  if (users_.empty()) {
    return;
  }
  const auto comms = live_communicators();
  if (comms.empty()) {
    return;
  }
  // Enroll each hosted user with the communicators responsible for its id.
  for (auto& [uid, lu] : users_) {
    if (now < lu.next_register) {
      continue;
    }
    const std::vector<tier::crypto::Byte> frame = tier::msg::make_user_register(
        lu.identity.public_key(),
        tier::crypto::ByteSpan(lu.device_credential.data(),
                               lu.device_credential.size()),
        now_unix, now_unix + kUserEnrollTtlSeconds);
    const auto responsible =
        responsible_communicators(uid, comms, kPresenceReplicas);
    for (const auto& c : responsible) {
      const auto conn = conn_by_peer_.find(c);
      if (conn != conn_by_peer_.end()) {
        endpoint_.send(conn->second, frame);
      } else if (const auto info = membership_.find(c); info) {
        dial_addresses(info->addresses, now);
      }
    }
    lu.next_register = now + kUserRegisterInterval;
  }
}

void Node::service_user_sends(std::chrono::steady_clock::time_point now) {
  for (auto it = pending_user_sends_.begin(); it != pending_user_sends_.end();) {
    const tier::core::PeerId user = it->first;
    auto& queue = it->second;

    queue.erase(std::remove_if(queue.begin(), queue.end(),
                               [&](const PendingUserSend& m) {
                                 return now >= m.deadline;
                               }),
                queue.end());
    if (queue.empty()) {
      user_lookup_sent_.erase(user);
      it = pending_user_sends_.erase(it);
      continue;
    }

    const auto last = user_lookup_sent_.find(user);
    if (last == user_lookup_sent_.end() ||
        now - last->second >= kLookupRetryInterval) {
      const auto comms = live_communicators();
      const auto responsible =
          responsible_communicators(user, comms, kPresenceReplicas);
      bool asked = false;
      for (const auto& c : responsible) {
        const auto conn = conn_by_peer_.find(c);
        if (conn != conn_by_peer_.end()) {
          endpoint_.send(conn->second, tier::msg::make_user_lookup(user));
          asked = true;
        } else if (const auto info = membership_.find(c); info) {
          dial_addresses(info->addresses, now);
        }
      }
      if (asked) {
        user_lookup_sent_[user] = now;
      }
    }
    ++it;
  }
}

Node::SendResult Node::send_as_user(const tier::core::PeerId& from_user,
                                    const tier::core::PeerId& to_user,
                                    tier::msg::Suite suite,
                                    std::span<const tier::crypto::Byte> plaintext) {
  if (users_.find(from_user) == users_.end()) {
    return SendResult::failed;  // from_user is not hosted here
  }
  PendingUserSend pending;
  pending.from_user = from_user;
  pending.suite = suite;
  pending.plaintext.assign(plaintext.begin(), plaintext.end());
  pending.deadline = std::chrono::steady_clock::now() + kPendingSendTimeout;

  // If the recipient user is hosted on this same node, deliver that copy locally
  // right away (loopback) and mark our own device done so the network fan-out
  // skips it. The user may also have remote devices, so we still resolve + queue.
  if (users_.find(to_user) != users_.end()) {
    ReceivedMessage rx;
    rx.sender = self_id_;
    rx.suite = suite;
    rx.sender_user = from_user;
    rx.recipient_user = to_user;
    rx.plaintext.assign(plaintext.begin(), plaintext.end());
    // User messages are not buffered on the node; the loopback copy is emitted
    // via the callback to the application layer, same as a networked one.
    if (on_message_received_) {
      on_message_received_(rx);
    }
    pending.delivered.insert(self_id_);
  }

  pending_user_sends_[to_user].push_back(std::move(pending));
  service_user_sends(std::chrono::steady_clock::now());
  return SendResult::queued;
}

bool Node::deliver_sealed(const tier::core::PeerId& to, tier::msg::Suite suite,
                          std::span<const tier::crypto::Byte> plaintext) {
  const auto conn = conn_by_peer_.find(to);
  if (conn == conn_by_peer_.end()) {
    return false;  // not connected
  }
  const auto keys = peer_enc_keys_.find(to);
  if (keys == peer_enc_keys_.end()) {
    return false;  // encryption keys not known
  }
  tier::msg::Recipient recipient;
  recipient.id = to;
  recipient.keys = keys->second;
  const std::vector<tier::crypto::Byte> sealed =
      tier::msg::seal(identity_, network_, suite, recipient, plaintext);
  endpoint_.send(conn->second, sealed);
  return true;
}

Node::SendResult Node::send_framed(const tier::core::PeerId& to,
                                   tier::msg::Suite suite,
                                   std::vector<tier::crypto::Byte> framed) {
  // Fast path: already connected with known keys.
  if (deliver_sealed(to, suite,
                     std::span<const tier::crypto::Byte>(framed.data(), framed.size()))) {
    return SendResult::sent;
  }
  // Cannot reach a plain client without a communicator to resolve it through,
  // and never route to ourselves.
  if (to == self_id_) {
    return SendResult::failed;
  }
  // Queue it; the poll loop resolves the peer (presence lookup), connects, and
  // flushes. seal() copies the plaintext at delivery, so keep our own copy now.
  PendingSend pending;
  pending.suite = suite;
  pending.plaintext = std::move(framed);
  pending.deadline = std::chrono::steady_clock::now() + kPendingSendTimeout;
  pending_sends_[to].push_back(std::move(pending));
  // Kick resolution immediately so a reachable peer flushes on the next poll.
  service_pending_sends(std::chrono::steady_clock::now());
  return SendResult::queued;
}

Node::SendResult Node::send_message(
    const tier::core::PeerId& to, tier::msg::Suite suite,
    std::span<const tier::crypto::Byte> plaintext) {
  // Frame as a plain node (device-to-device) message and hand to the common
  // path. The kind tag is stripped by the receiver; callers see only the body.
  std::vector<tier::crypto::Byte> framed;
  framed.reserve(plaintext.size() + 1);
  framed.push_back(kAppKindNode);
  framed.insert(framed.end(), plaintext.begin(), plaintext.end());
  return send_framed(to, suite, std::move(framed));
}

bool Node::has_encryption_keys(const tier::core::PeerId& peer) const {
  return peer_enc_keys_.find(peer) != peer_enc_keys_.end();
}

std::vector<Node::ReceivedMessage> Node::take_inbox() {
  std::vector<ReceivedMessage> out;
  out.swap(inbox_);
  return out;
}

void Node::on_message_received(std::function<void(const ReceivedMessage&)> cb) {
  on_message_received_ = std::move(cb);
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

void Node::retry_seeds(std::chrono::steady_clock::time_point now) {
  // Only retry while we have no live neighbor: once connected, anti-entropy and
  // autodial over the learned membership take over. This is the recovery path
  // for a node that outlived every connection or started before its seed.
  if (!conn_by_peer_.empty()) {
    return;
  }
  const auto self = membership_.find(self_id_);
  for (auto& [addr, state] : seed_retry_) {
    if (now < state.next || !is_dialable(addr) || addr == self_address_) {
      continue;
    }
    if (self && std::find(self->addresses.begin(), self->addresses.end(),
                          addr) != self->addresses.end()) {
      continue;  // this seed is one of our own advertised addresses
    }
    const auto hp = split_host_port(addr);
    if (!hp) {
      continue;
    }
    try {
      endpoint_.connect(hp->first, hp->second);
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
      // Unroutable right now; the backoff below still advances so we do not spin.
    }
    dialed_[addr] = now;
    // Capped exponential backoff with jitter: 1s, 2s, 4s, ... up to 30s, each
    // spread +/-25% so a fleet restarting together does not synchronize its
    // reconnect attempts.
    const unsigned shift = state.attempts < 5 ? state.attempts : 5;
    const auto base = std::chrono::seconds(1) * (1U << shift);
    const auto capped = std::min<std::chrono::steady_clock::duration>(
        base, std::chrono::seconds(30));
    std::uniform_int_distribution<int> jitter(-25, 25);
    const auto delay = capped + (capped * jitter(rng_)) / 100;
    state.next = now + delay;
    if (state.attempts < 1000) {
      ++state.attempts;
    }
  }
}

void Node::autodial(std::chrono::steady_clock::time_point now) {
  retry_seeds(now);

  // Bounded degree (docs/topology.md, Phase 2): compute which backbone peers we
  // should connect to - our ring neighbors if we are backbone, or a small set of
  // entry points if we are an edge node - rather than dialing every backbone we
  // know. The id list drives both: build it once from the live backbone, sorted.
  const bool self_backbone = tier::core::is_infrastructure(roles_);
  std::vector<tier::core::PeerId> live_backbone;
  for (const tier::core::PeerInfo& p : membership_.snapshot()) {
    if (tier::core::is_infrastructure(p.roles) &&
        p.liveness != tier::core::Liveness::dead) {
      live_backbone.push_back(p.id);  // includes self iff self is backbone
    }
  }
  std::sort(live_backbone.begin(), live_backbone.end());
  const auto target_vec = ring_dial_targets(live_backbone, self_id_,
                                            self_backbone, kBackboneDegree,
                                            kClientFanout);
  const std::set<tier::core::PeerId> targets(target_vec.begin(),
                                             target_vec.end());

  for (const tier::core::PeerInfo& p : membership_.snapshot()) {
    if (p.id == self_id_ || p.liveness == tier::core::Liveness::dead ||
        conn_by_peer_.count(p.id) != 0) {
      continue;
    }
    // Topology by role (docs/topology.md): an edge node (plain client) is never
    // a dial target. It reaches the network by dialing infrastructure and is
    // served over the connection it opened, so nobody dials it. Only
    // infrastructure peers are autodial candidates. Seeds are dialed separately
    // (retry_seeds), by address, before their role is known.
    if (!tier::core::is_infrastructure(p.roles)) {
      continue;
    }
    // Bounded degree: only dial backbone peers in our ring-neighbor / entry-point
    // target set, so the connection count does not grow with the backbone size.
    if (targets.count(p.id) == 0) {
      continue;
    }
    // Exactly one side initiates each connection. Between two infrastructure
    // nodes the lower id dials, so a pair ends up with one connection rather
    // than two crossing ones (the target relation is symmetric for backbone, so
    // both agree the edge should exist). An edge node is always the initiator
    // toward infrastructure (the tie-break does not apply), because
    // infrastructure never dials an edge node back.
    if (self_backbone && !(self_id_ < p.id)) {
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
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
      // A malformed or unroutable gossiped address must not take us down; the
      // backoff above keeps us from retrying it in a tight loop.
    }
  }
}

}  // namespace tier::net
