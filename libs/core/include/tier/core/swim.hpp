#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <vector>

#include "tier/core/membership.hpp"

namespace tier::core {

// Timing of the SWIM failure detector. Defaults are production-oriented; tests
// shrink them to run the state machine in milliseconds.
struct SwimConfig {
  // One peer is probed per period.
  std::chrono::milliseconds probe_period{1000};
  // Within a period, if no direct ack arrives by this point, fan out indirect
  // probes. Must be < probe_period.
  std::chrono::milliseconds ping_timeout{400};
  // A peer stays suspect this long before it is declared dead, unless it refutes
  // the suspicion first by raising its incarnation. Must be >> gossip latency so
  // a live peer's refutation always arrives first.
  std::chrono::milliseconds suspicion_timeout{5000};
  // A dead peer is kept (and gossiped) this long before being removed, so the
  // death disseminates before the entry disappears.
  std::chrono::milliseconds dead_cleanup{30000};
  // Number of relays asked to probe a target indirectly.
  std::size_t indirect_probes{3};
};

// SWIM/Lifeguard failure detector. Transport-agnostic: it reads and mutates a
// Membership table and emits point-to-point probe messages through a send
// callback; the caller wires those to a real transport and feeds back received
// messages. The clock is injected (every call takes `now`) so the whole state
// machine is deterministic under test.
//
// Suspicion and death are disseminated by the caller's existing anti-entropy
// gossip of the Membership table, not by this detector: it only writes the
// suspect/dead/alive transitions into the table. A node refutes a suspicion of
// itself by incrementing its own incarnation (which supersedes the suspicion
// everywhere once gossiped).
class FailureDetector {
 public:
  using Clock = std::chrono::steady_clock;

  // Deliver a SWIM control message to a peer identified by its stable id. The
  // wiring layer routes it over whatever connection reaches that peer; if none
  // does it may drop the message, and the probe simply times out.
  using SendFn =
      std::function<void(const PeerId& to, const std::vector<std::uint8_t>& msg)>;

  FailureDetector(PeerId self, Membership& membership, SwimConfig cfg,
                  SendFn send);

  // Advance the protocol. `neighbors` are the peers currently reachable over a
  // direct connection; probe targets and indirect relays are drawn from them.
  // Call this regularly with the current time.
  void tick(Clock::time_point now, const std::vector<PeerId>& neighbors);

  // Feed one received control message. Returns true if it was a SWIM message
  // (ping/ack/ping_req) and has been handled; false otherwise (e.g. a
  // membership snapshot), so the caller can process it itself.
  bool handle(Clock::time_point now, const PeerId& from,
              std::span<const std::uint8_t> msg);

 private:
  void refute_if_accused();
  void scan_membership(Clock::time_point now);
  void advance_suspicions(Clock::time_point now);
  void expire_relays(Clock::time_point now);
  void check_probe_timeouts(Clock::time_point now,
                            const std::vector<PeerId>& neighbors);
  void start_probe(Clock::time_point now, const std::vector<PeerId>& neighbors);
  void suspect(const PeerId& id, Clock::time_point now);

  PeerId self_;
  Membership& m_;
  SwimConfig cfg_;
  SendFn send_;

  std::uint64_t next_seq_ = 1;

  // Our outstanding probes, keyed by the seq we put in the ping.
  struct Probe {
    PeerId target{};
    Clock::time_point sent{};
    bool indirect_sent = false;
  };
  std::map<std::uint64_t, Probe> pending_;

  // Indirect probes we are relaying for someone else: the ping we sent to the
  // target (keyed by its seq) maps back to who asked and under what seq.
  struct Relay {
    PeerId requester{};
    std::uint64_t orig_seq = 0;
    Clock::time_point when{};
  };
  std::map<std::uint64_t, Relay> relaying_;

  // Peers we currently hold as suspect, with when suspicion began and at which
  // incarnation (a higher incarnation refutes it).
  struct Suspicion {
    Clock::time_point since{};
    std::uint64_t incarnation = 0;
  };
  std::map<PeerId, Suspicion> suspects_;

  // Peers held as dead, with when we first saw them dead (for cleanup).
  std::map<PeerId, Clock::time_point> dead_since_;

  Clock::time_point last_probe_{};
  bool probing_started_ = false;
  std::size_t rr_ = 0;  // round-robin cursor over neighbors
};

}  // namespace tier::core
