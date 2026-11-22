#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "envelope.hpp"

namespace tier::agent {

// Collector-side store: rewritable gauges (last value per sender+key) and an
// append-only event history. Durable via an append log that is replayed on
// start. De-duplication keeps a bounded set of recently seen message ids. This
// is deliberately a standalone module: a future keeper reuses it and wraps HA/
// replication around the same gauge+event semantics.
class Store {
 public:
  // Opens (creating if needed) the append log at `path` and replays it. An empty
  // path keeps the store in memory only (no persistence) - used by tests.
  explicit Store(std::string path);

  // Returns true the first time a msg_id is seen, false for a duplicate (which
  // the caller should drop). Bounded memory; very old ids are forgotten.
  bool first_seen(const std::array<std::uint8_t, 16>& msg_id);

  // Apply one authenticated message's samples: overwrite gauges, append events,
  // and persist. `sender_hex` is the authenticated sending user id (hex).
  void apply(const std::string& sender_hex, const Envelope& env);

  // Human-readable snapshot: current gauges then recent events.
  [[nodiscard]] std::string render() const { return query(std::string{}); }

  // Like render(), but keeps only entries whose "sender/key" label contains the
  // substring `needle` (an empty needle matches everything). Used by the local
  // read interface.
  [[nodiscard]] std::string query(const std::string& needle) const;

  [[nodiscard]] std::size_t gauge_count() const { return gauges_.size(); }
  [[nodiscard]] std::size_t event_count() const { return events_.size(); }

 private:
  struct Gauge {
    std::string value;
    std::uint64_t ts_unix = 0;
  };
  struct Event {
    std::string sender;
    std::string key;
    std::string value;
    std::uint64_t ts_unix = 0;
  };

  void record(const std::string& sender_hex, const Sample& s,
              std::uint64_t ts_unix, bool persist);

  std::string path_;
  std::map<std::string, Gauge> gauges_;  // key = sender_hex + '\x1f' + metric
  std::deque<Event> events_;             // bounded ring of recent events

  std::unordered_set<std::string> seen_;  // msg_id (raw 16 bytes as string)
  std::deque<std::string> seen_order_;    // FIFO to bound seen_
};

}  // namespace tier::agent
