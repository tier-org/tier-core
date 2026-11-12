#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/core/swim.hpp"
#include "tier/core/version_range.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/holepunch.hpp"
#include "tier/msg/presence.hpp"
#include "tier/msg/sealed.hpp"
#include "tier/msg/user.hpp"
#include "tier/net/endpoint.hpp"
#include "tier/net/presence_registry.hpp"
#include "tier/net/rendezvous.hpp"
#include "tier/net/user_directory.hpp"

namespace tier::net {

// A network participant: a QUIC endpoint plus the membership view it maintains.
// On every connection the two peers exchange their membership snapshots and
// merge them (anti-entropy, one round for now). This is the control plane of
// the base layer; it carries node identities, roles and liveness, never user
// application messages.
class Node {
 public:
  // `roles` is the set of roles this node holds (tier::core::role_bit(...),
  // OR'd for several). A plain participant passes role_bit(Role::client).
  // `network` is the cluster this node joins (mainnet by default). It is folded
  // into the transport ALPN, so a node only ever connects to, and gossips with,
  // peers on the same network - even if they share a seed address.
  // `version_range` is this network's software-version policy: a gossiped peer
  // whose advertised version falls outside it is not admitted to membership.
  // Default (unconstrained) admits every version.
  Node(tier::crypto::NodeIdentity identity, tier::core::RoleSet roles,
       const std::string& ip, std::uint16_t port,
       tier::core::SwimConfig swim = {}, std::string network = "mainnet",
       tier::core::VersionRange version_range = {});

  [[nodiscard]] std::uint16_t local_port() const noexcept;

  // This node's membership id: SHA-256 of its public key.
  [[nodiscard]] const tier::core::PeerId& peer_id() const noexcept;

  // The network (cluster) this node joined. Node-wide, not carried per peer:
  // membership only ever holds peers on this same network.
  [[nodiscard]] const std::string& network() const noexcept;

  void connect(const std::string& ip, std::uint16_t port);

  // Dial a set of bootstrap addresses ("ip:port", IPv6 bracketed) once at
  // startup, typically tier::core::default_seed_addresses(). Addresses this
  // node already advertises (its own) are skipped so a seed does not dial
  // itself; any other address is fine even for an unknown peer, since peer
  // identities are learned from the handshake and membership fills in from
  // there. Malformed addresses are ignored.
  void bootstrap(const std::vector<std::string>& seeds);

  void poll(int timeout_ms);

  [[nodiscard]] const tier::core::Membership& membership() const noexcept;

  // Peers this node currently holds a live connection to (handshake complete).
  [[nodiscard]] std::vector<tier::core::PeerId> connected_peers() const;

  // --- end-to-end encrypted application messages -------------------------
  // A decrypted, sender-authenticated message handed up from the control
  // plane. `sender` is the authenticated peer id (it hashes to the identity
  // key the message was signed with).
  struct ReceivedMessage {
    tier::core::PeerId sender{};  // authenticated sender device id
    tier::msg::Suite suite{};
    std::vector<tier::crypto::Byte> plaintext;
    // Both set when the message was a user message whose credential verified:
    // the authenticated sender user id, and which local user it was addressed to
    // (a device may host several users). Unset for a plain node (device-to-device)
    // message. See docs/multi-identity.md.
    std::optional<tier::core::PeerId> sender_user;
    std::optional<tier::core::PeerId> recipient_user;
  };

  // Outcome of a send_message call.
  enum class SendResult : std::uint8_t {
    sent,    // sealed and handed to the transport on an existing connection
    queued,  // held pending discovery/connection; delivered or dropped later
    failed,  // could not be accepted (e.g. no way to reach the peer at all)
  };

  // Send an encrypted message to a peer under `suite`. If the peer is already
  // connected and its encryption keys are known, the message is sealed and sent
  // immediately (`sent`). Otherwise it is queued and the node resolves the peer
  // via a communicator (presence lookup), connects directly, and flushes the
  // message when ready (`queued`); it is dropped if that does not complete
  // before a timeout. `failed` means the send could not even be queued. Throws
  // only on an unexpected crypto backend failure. See docs/communicator.md.
  [[nodiscard]] SendResult send_message(
      const tier::core::PeerId& to, tier::msg::Suite suite,
      std::span<const tier::crypto::Byte> plaintext);

  // Whether this node currently holds the encryption keys for a peer (i.e. the
  // peer is reachable for send_message).
  [[nodiscard]] bool has_encryption_keys(const tier::core::PeerId& peer) const;

  // --- multi-identity (see docs/multi-identity.md) -----------------------
  // Host a user identity on this device (many may coexist, all added and removed
  // at runtime). The node self-issues this device's credential under the user
  // key and begins publishing a user-directory enrollment so the user is
  // addressable. Returns the user id. A node hosting no user identity still sends
  // and receives plain node (device-to-device) messages as before.
  tier::core::PeerId add_user(tier::crypto::NodeIdentity user);

  // Stop hosting a user identity. Its directory enrollment is left to expire.
  // Returns true if the user was hosted here.
  bool remove_user(const tier::core::PeerId& user_id);

  // The user ids currently hosted on this node.
  [[nodiscard]] std::vector<tier::core::PeerId> user_ids() const;

  // Whether a user id is hosted on this node.
  [[nodiscard]] bool has_user(const tier::core::PeerId& user_id) const;

  // Test-only: simulate a restricted NAT in front of this node (see
  // Endpoint::set_simulated_restricted_nat). Lets NAT traversal be tested
  // without a real NAT. Never call on a live node.
  void set_simulated_restricted_nat(bool on);

  // Send an encrypted message from a local user (`from_user`, which must be
  // hosted here) to `to_user` (all of whose currently-online devices receive
  // it). Resolves the recipient's devices through a communicator and fans the
  // message out as node-level sends, each carrying a user envelope that proves
  // the sending user and names the recipient user. A recipient device hosted on
  // this same node is delivered locally (loopback). With no storage, offline
  // devices simply miss it. Same sent/queued/failed contract as send_message.
  [[nodiscard]] SendResult send_as_user(
      const tier::core::PeerId& from_user, const tier::core::PeerId& to_user,
      tier::msg::Suite suite, std::span<const tier::crypto::Byte> plaintext);

  // Remove and return every plain node (device-to-device) message received
  // since the last call. User messages are not buffered here (online-only, see
  // docs/app-protocol.md); observe them through on_message_received.
  [[nodiscard]] std::vector<ReceivedMessage> take_inbox();

  // Invoked for each decrypted message as it arrives. This is the only delivery
  // path for user messages (which are not buffered); node messages also go to
  // take_inbox. Optional.
  void on_message_received(std::function<void(const ReceivedMessage&)> cb);

  // Invoked whenever a membership entry is newly learned or updated by a merge.
  void on_membership_change(std::function<void(const tier::core::PeerInfo&)> cb);

  // Dial policy for one peer's candidate addresses (static and pure, exposed
  // for testing). Returns the address to attempt next, or std::nullopt when
  // nothing is dialable or an attempt is still within `retry`. IPv6 candidates
  // are preferred; attempts to a single peer are serialized (one in flight per
  // `retry` window) and rotate across candidates, so an unreachable family is
  // not retried forever before the next one is tried.
  static std::optional<std::string> select_dial_candidate(
      const std::vector<std::string>& candidates,
      const std::map<std::string, std::chrono::steady_clock::time_point>& dialed,
      std::chrono::steady_clock::time_point now,
      std::chrono::steady_clock::duration retry);

  // Addresses observed by at least `threshold` distinct peers, sorted and
  // unique. A single dual-stack peer that has seen us over both families
  // contributes both, so a node reachable over IPv4 and IPv6 advertises both
  // (not just whichever family it was most recently dialed over).
  static std::vector<std::string> confirmed_addresses(
      const std::map<tier::core::PeerId, std::set<std::string>>& observed,
      std::size_t threshold);

  // Which backbone peers this node should hold a connection to, given the sorted
  // list of live backbone ids (docs/topology.md, Phase 2). Instead of a full
  // mesh among infrastructure, a backbone node connects to its ring neighbors -
  // the `k_backbone/2` successors and predecessors by id on the circular id
  // space - a connected, redundant graph whose degree does not grow with the
  // backbone size. The relation is symmetric (B is A's neighbor iff A is B's),
  // so the one-dials-the-other tie-break still yields a single connection. An
  // edge node instead targets `k_client` backbone nodes (its id-successors), a
  // small redundant set of entry points. `sorted_backbone` must be sorted,
  // unique, and include `self` iff `self_is_backbone`.
  static std::vector<tier::core::PeerId> ring_dial_targets(
      const std::vector<tier::core::PeerId>& sorted_backbone,
      const tier::core::PeerId& self, bool self_is_backbone,
      std::size_t k_backbone, std::size_t k_client);

 private:
  void push_membership(ConnId conn);
  void merge_message(std::span<const tier::crypto::Byte> payload);
  // Records that propagate network-wide: infrastructure (backbone) peers and
  // our own record. A plain-client (edge) record is held only by the backbone
  // it attaches to and is never re-gossiped, so the global membership stays the
  // small, stable backbone set (docs/topology.md, Phase 3a).
  [[nodiscard]] bool should_propagate(const tier::core::PeerInfo& p) const noexcept;
  // The snapshot filtered to should_propagate records - what we gossip.
  [[nodiscard]] std::vector<tier::core::PeerInfo> gossip_records() const;
  // Queue a changed record for immediate rumor-push to neighbors this poll
  // (Phase 3b). Only propagated records are queued; the periodic full
  // anti-entropy is the backstop for anything a rumor missed.
  void queue_rumor(const tier::core::PeerInfo& p);
  // Whether an id is within its demotion-propagation window (see demoted_until_
  // and merge_message): a node that transitioned from an infrastructure role to
  // plain client. Such a record is not propagated by role (it is now a client),
  // but the revocation of its former backbone status must still reach the whole
  // network, so it is gossiped like a propagated record for a bounded window
  // (docs/topology.md, A6). Without this, downstream peers keep the stale
  // infrastructure record and may still dial the node as backbone.
  [[nodiscard]] bool demotion_active(
      const tier::core::PeerId& id,
      std::chrono::steady_clock::time_point now) const;
  // Reconcile a gossiped record about ourselves. Our roles and version are
  // locally authoritative and our addresses are learned via observed_addr, so a
  // relayed self-record - even one validly signed by a previous run of this key
  // - is never merged over them. If it could supersede our current record
  // (incarnation at least ours) and differs from what we assert, we refute it
  // the SWIM way: raise our incarnation above it and re-broadcast our
  // authoritative record. This also recovers after a restart that reset our
  // incarnation or changed our configured role.
  void reconcile_self(const tier::core::PeerInfo& relayed);
  // Seal our own record: stamp our public key and sign the owner-asserted fields
  // for this network, so peers can verify the record we gossip is ours. Called
  // whenever our own id/roles/version/addresses/incarnation change.
  void seal_self(tier::core::PeerInfo& me) const;
  // Verify a gossiped record is authentic: its id is the hash of the public key
  // it carries, and its signature over the owner-asserted fields checks out
  // against that key for this network. A record that fails is dropped, not
  // merged, so no peer can forge another's roles, version, addresses or
  // incarnation. Liveness is not signed (it is a third-party SWIM assertion).
  [[nodiscard]] bool verify_owner(const tier::core::PeerInfo& p) const;
  // Record a peer's report of the address it observes us at; adopt it as our
  // advertised address once enough peers agree.
  void handle_observed(const tier::core::PeerId& from,
                       std::span<const tier::crypto::Byte> payload);
  // Verify a peer's signed enc_keys announce (against the identity key it
  // authenticated with) and cache its encryption keys, so we can send it
  // encrypted messages. A failed verification is dropped.
  void handle_enc_keys(const tier::core::PeerId& from, const PeerId& sender_key,
                       std::span<const tier::crypto::Byte> payload);
  // Open a sealed application message and deliver it to the inbox. The sealed
  // layer authenticates the sender against `sender_key` and checks it is
  // addressed to us; a message that fails any check is dropped.
  void handle_sealed(const PeerId& sender_key,
                     std::span<const tier::crypto::Byte> payload);
  // --- client-to-client discovery (see docs/communicator.md) ---------------
  // Communicator side: verify and store a client's signed presence record.
  void handle_presence_register(std::span<const tier::crypto::Byte> payload,
                                std::uint64_t now_unix);
  // Communicator side: answer a lookup on `conn` with the stored record (or a
  // not-found marker).
  void handle_presence_lookup(ConnId conn,
                              std::span<const tier::crypto::Byte> payload,
                              std::uint64_t now_unix);
  // Resolver side: verify a returned record, cache the peer's keys/addresses,
  // and dial it so a queued message can flush.
  void handle_presence_result(std::span<const tier::crypto::Byte> payload,
                              std::chrono::steady_clock::time_point now);
  // Live communicator ids from the current membership (alive, communicator
  // role), used to compute rendezvous responsibility.
  [[nodiscard]] std::vector<tier::core::PeerId> live_communicators() const;
  // If this node is an edge client, (re)publish its presence record to the
  // communicators responsible for its id, dialing one if not yet connected.
  void register_presence(std::chrono::steady_clock::time_point now,
                         std::uint64_t now_unix);
  // Drive queued sends: flush any whose peer is now connected with known keys,
  // (re)issue a lookup or direct dial for the rest, and drop timed-out ones.
  void service_pending_sends(std::chrono::steady_clock::time_point now);
  // Seal and transmit one message to an already-connected peer whose keys are
  // known. Returns false if the peer is not currently reachable this way.
  bool deliver_sealed(const tier::core::PeerId& to, tier::msg::Suite suite,
                      std::span<const tier::crypto::Byte> plaintext);
  // Send already-framed application bytes (a kind tag + body) to a device: fast
  // path if connected with known keys, else queue for resolution. The public
  // send_message and the user fan-out both frame their payload and call this.
  SendResult send_framed(const tier::core::PeerId& to, tier::msg::Suite suite,
                         std::vector<tier::crypto::Byte> framed);
  // Dial the first dialable of `addresses` (rate-limited via dialed_), if not
  // already connected to `id`.
  void dial_addresses(const std::vector<std::string>& addresses,
                      std::chrono::steady_clock::time_point now);
  // --- multi-identity directory (see docs/multi-identity.md) ---------------
  // Communicator side: verify a device enrollment (its credential must bind the
  // connection's device id to the carried user key) and store it.
  void handle_user_register(const tier::core::PeerId& from_device,
                            std::span<const tier::crypto::Byte> payload,
                            std::uint64_t now_unix);
  // Communicator side: answer a user lookup on `conn` with the enrolled devices.
  void handle_user_lookup(ConnId conn,
                          std::span<const tier::crypto::Byte> payload,
                          std::uint64_t now_unix);
  // Sender side: on a user result, fan the queued message(s) for that user out
  // to each returned device.
  void handle_user_result(std::span<const tier::crypto::Byte> payload,
                          std::chrono::steady_clock::time_point now);
  // Fan the queued message(s) for `user` out to each of `devices` (skipping the
  // local device and any already delivered to). Shared by handle_user_result
  // (devices from a communicator's reply) and the local-directory fast path in
  // service_user_sends used when this node is itself a responsible communicator.
  void deliver_resolved_user(const tier::core::PeerId& user,
                             const std::vector<tier::core::PeerId>& devices);
  // If a user identity is attached, (re)publish this device's enrollment to the
  // communicators responsible for the user id.
  void register_user(std::chrono::steady_clock::time_point now,
                     std::uint64_t now_unix);
  // Drive queued user-level sends: (re)issue a user lookup, drop timed-out ones.
  void service_user_sends(std::chrono::steady_clock::time_point now);
  // --- NAT hole punching (see docs/communicator.md, M-NAT) -----------------
  // Communicator side: relay a punch request to its target as a signal.
  void handle_hole_punch_request(ConnId conn, const tier::core::PeerId& from,
                                 std::span<const tier::crypto::Byte> payload);
  // Target side: dial the origin's candidates and, on an initiate, reply so the
  // origin dials ours too (coordinated simultaneous open).
  void handle_hole_punch_signal(ConnId conn,
                                std::span<const tier::crypto::Byte> payload,
                                std::chrono::steady_clock::time_point now);
  // Our own candidate addresses (what we advertise), for a punch.
  [[nodiscard]] std::vector<std::string> self_candidates() const;
  // Ask the communicator responsible for `target` to coordinate a punch to it.
  void initiate_hole_punch(const tier::core::PeerId& target,
                           std::chrono::steady_clock::time_point now);
  // Dial known peers we have learned of but are not yet connected to, forming a
  // mesh out of transitive discovery.
  void autodial(std::chrono::steady_clock::time_point now);
  // Re-dial the bootstrap seeds while we have no neighbors, with capped
  // exponential backoff and jitter, so a node that started before its seed (or
  // lost every connection) reconnects without a restart or a manual bootstrap.
  void retry_seeds(std::chrono::steady_clock::time_point now);

  tier::crypto::NodeIdentity identity_;
  tier::core::PeerId self_id_;
  // Our configured roles: locally authoritative, never redefined by a gossiped
  // record (see reconcile_self). Version is likewise authoritative and always
  // tier::core::version().
  tier::core::RoleSet roles_;
  // The cluster this node joins; bound into each record's signature so a record
  // signed for one network cannot be replayed into another.
  std::string network_;
  tier::core::Membership membership_;
  Endpoint endpoint_;
  std::string self_address_;
  std::function<void(const tier::core::PeerInfo&)> on_change_;
  // Periodic full anti-entropy clock (Phase 3b backstop). Timely propagation is
  // driven by rumor-push on change; this full resync is the infrequent safety
  // net that heals anything a rumor missed.
  std::chrono::steady_clock::time_point last_full_sync_{};
  // Records changed this poll, flushed as a single rumor message to neighbors at
  // the end of poll() and then cleared.
  std::vector<tier::core::PeerInfo> rumor_queue_;
  // Peers that just dropped from an infrastructure role to plain client, mapped
  // to the time their demotion stops being gossiped network-wide. While present
  // and unexpired, the peer's (now client) record is included in gossip and
  // anti-entropy so the demotion reaches every node, not just the immediate
  // neighbor that received it; expired entries are pruned each poll. See
  // merge_message and demotion_active (docs/topology.md, A6).
  std::map<tier::core::PeerId, std::chrono::steady_clock::time_point>
      demoted_until_;
  // Peer id -> live connection, rebuilt from the endpoint each poll; the failure
  // detector sends probes by peer id and this routes them.
  std::map<tier::core::PeerId, ConnId> conn_by_peer_;
  // Per peer id, the encryption keys it announced (enc_keys). Populated on
  // handshake; required to seal a message to that peer. Also filled from a
  // resolved presence record when reaching a peer we are not yet connected to.
  std::map<tier::core::PeerId, tier::msg::PeerEncKeys> peer_enc_keys_;
  // --- client-to-client discovery state (see docs/communicator.md) ---------
  // Communicator role only: the bounded store of client presence records.
  PresenceRegistry presence_registry_;
  // A message waiting for its peer to be reachable.
  struct PendingSend {
    tier::msg::Suite suite;
    std::vector<tier::crypto::Byte> plaintext;
    std::chrono::steady_clock::time_point deadline;
  };
  // Target peer id -> messages queued for it while discovery/connection is in
  // flight (send_message to an unconnected peer).
  std::map<tier::core::PeerId, std::vector<PendingSend>> pending_sends_;
  // Target peer id -> addresses learned from its resolved presence record, used
  // to dial it directly.
  std::map<tier::core::PeerId, std::vector<std::string>> resolved_addrs_;
  // Target peer id -> when we last sent a presence lookup for it, to rate-limit
  // repeated lookups while a resolution is pending.
  std::map<tier::core::PeerId, std::chrono::steady_clock::time_point>
      lookup_sent_;
  // When this (edge client) node may next publish its presence record.
  std::chrono::steady_clock::time_point next_presence_register_{};
  // Communicators this node last published its presence to. The responsible set
  // depends on the live communicator set, so it shifts as membership converges
  // or a communicator joins/leaves; a change must trigger an immediate re-publish
  // rather than waiting for the refresh timer.
  std::vector<tier::core::PeerId> presence_published_to_{};
  // --- multi-identity state (see docs/multi-identity.md) -------------------
  // User identities hosted on this device, keyed by user id. Each carries its
  // own self-issued device credential (this device signed by the user key) and
  // its own directory re-enrollment schedule. Added and removed at runtime; a
  // node may host zero, one, or many.
  struct LocalUser {
    tier::crypto::NodeIdentity identity;
    std::vector<tier::crypto::Byte> device_credential;
    std::chrono::steady_clock::time_point next_register{};
    // The responsible-communicator set this user was last enrolled against. When
    // it changes (membership converged, a communicator joined or left, so the
    // rendezvous shifted) we must re-enroll at once rather than wait out the
    // refresh interval - otherwise the entry sits on the wrong nodes and lookups
    // (which use the current set) miss it.
    std::vector<tier::core::PeerId> enrolled_to{};
  };
  std::map<tier::core::PeerId, LocalUser> users_;
  // Communicator role only: user id -> enrolled device ids.
  UserDirectory user_directory_;
  // A user-level message waiting for the recipient user's devices to be
  // resolved. `from_user` is the local user it is sent on behalf of.
  struct PendingUserSend {
    tier::core::PeerId from_user{};
    tier::msg::Suite suite;
    std::vector<tier::crypto::Byte> plaintext;
    std::chrono::steady_clock::time_point deadline;
    // Devices this message has already been fanned out to. The user's device
    // set is resolved repeatedly (devices enroll asynchronously and a lookup
    // can land before a device has registered), so we deliver to each newly
    // seen device exactly once and keep the send alive until its deadline.
    std::set<tier::core::PeerId> delivered;
  };
  std::map<tier::core::PeerId, std::vector<PendingUserSend>> pending_user_sends_;
  // Target user id -> when we last sent a user lookup, to rate-limit lookups.
  std::map<tier::core::PeerId, std::chrono::steady_clock::time_point>
      user_lookup_sent_;
  // --- hole-punch state (see docs/communicator.md, M-NAT) ------------------
  // Target id -> earliest time to escalate a stuck direct dial to a hole punch
  // (set when we first resolve the peer's addresses), and -> when we last sent a
  // punch request for it (rate-limit).
  std::map<tier::core::PeerId, std::chrono::steady_clock::time_point> punch_grace_;
  std::map<tier::core::PeerId, std::chrono::steady_clock::time_point> punch_sent_;
  // Decrypted messages received and not yet drained by take_inbox().
  std::vector<ReceivedMessage> inbox_;
  std::function<void(const ReceivedMessage&)> on_message_received_;
  // Per reporting peer, the set of addresses it has observed us at
  // (observed_addr). A peer that has connected to us over both IPv4 and IPv6
  // reports each, so this accumulates rather than overwrites.
  std::map<tier::core::PeerId, std::set<std::string>> observed_;
  // Per dialed "ip:port", when we last issued a connect, to rate-limit redials
  // and avoid a duplicate connection to a peer whose handshake is still pending.
  std::map<std::string, std::chrono::steady_clock::time_point> dialed_;
  // Bootstrap seed addresses kept for re-dialing (see retry_seeds), with per
  // seed backoff state: when it may next be attempted and how many attempts have
  // failed (to grow the delay).
  std::vector<std::string> seeds_;
  struct SeedRetry {
    std::chrono::steady_clock::time_point next{};
    unsigned attempts = 0;
  };
  std::map<std::string, SeedRetry> seed_retry_;
  std::mt19937 rng_;
  // This network's version policy; a gossiped peer outside it is not admitted
  // (see merge_message). Unconstrained by default.
  tier::core::VersionRange version_range_;
  tier::core::FailureDetector fd_;
};

}  // namespace tier::net
