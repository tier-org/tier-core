#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "envelope.hpp"
#include "sink.hpp"

namespace tier::agent {

// Tuning for the local file sink's on-disk layout and retention.
struct StoreOptions {
  // Drop event segments whose whole time window is older than this. 0 = keep
  // forever (time-based retention disabled).
  std::uint64_t retention_secs = 7ULL * 24 * 3600;
  // Cap the total size of the event segments; when exceeded, oldest segments are
  // dropped first (never the active one). 0 = no size cap.
  std::uint64_t max_bytes = 0;
  // Cadence for writing the gauge snapshot and running the retention sweep. The
  // sweep is opportunistic (driven by writes and by flush()), so this is a floor
  // on how often maintenance runs, not a timer.
  std::uint32_t snapshot_interval_secs = 60;
  // Event segment window = retention granularity. One segment file per window.
  std::uint32_t segment_secs = 3600;
};

// Collector-side store and the built-in local Sink. Holds rewritable gauges
// (last value per sender+key) and an append-only event history, and backs the
// local query socket from that in-memory state.
//
// On-disk layout is a directory:
//   <dir>/gauges.snap            current gauges, rewritten atomically (snapshot)
//   <dir>/events-<win>.log       event segments, one per time window
// Gauges are last-value-wins, so they are snapshotted (not appended per update);
// events are appended to the current segment. Retention drops whole segments by
// age and/or total size - O(unlink), no rewrite - and segment filenames encode
// their window, so a future range reader can skip segments without opening them.
// On start the snapshot and the segments are replayed to rebuild memory.
//
// Segmentation and retention key off storage wall-clock time (not the sender's
// envelope ts), so a skewed or hostile sender cannot steer which segment data
// lands in or evade retention. De-duplication keeps a bounded set of recently
// seen message ids. The store is internally synchronized: the receive path and
// the query server call it concurrently.
class Store : public Sink {
 public:
  // Opens (creating if needed) the store directory `dir` and replays it. An
  // empty dir keeps the store in memory only (no persistence) - used by tests.
  explicit Store(std::string dir, StoreOptions opts = {});

  // Returns true the first time a msg_id is seen, false for a duplicate (which
  // the caller should drop). Bounded memory; very old ids are forgotten.
  bool first_seen(const std::array<std::uint8_t, 16>& msg_id);

  // Apply one authenticated message's samples: overwrite gauges, append events,
  // and persist. `sender_hex` is the authenticated sending user id (hex).
  void apply(const std::string& sender_hex, const Envelope& env);

  // Sink: the local store persists synchronously, so write() is just apply().
  void write(const std::string& sender_hex, const Envelope& env) override {
    apply(sender_hex, env);
  }

  // Sink: persist the gauge snapshot (if dirty) and run a retention sweep now.
  // Called on an interval and at shutdown.
  void flush() override;

  // Human-readable snapshot: current gauges then recent events.
  [[nodiscard]] std::string render() const { return query(std::string{}); }

  // Like render(), but keeps only entries whose "sender/key" label contains the
  // substring `needle` (an empty needle matches everything). Used by the local
  // read interface.
  [[nodiscard]] std::string query(const std::string& needle) const;

  [[nodiscard]] std::size_t gauge_count() const;
  [[nodiscard]] std::size_t event_count() const;

  // Test seam: override the clock used for segmentation and retention (default
  // is wall-clock time()). Set it before writing.
  void set_clock(std::function<std::uint64_t()> clock) {
    std::lock_guard<std::mutex> lk(mu_);
    clock_ = std::move(clock);
  }

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

  void load();  // replay snapshot + segments into memory (ctor, unlocked)
  void record(const std::string& sender_hex, const Sample& s,
              std::uint64_t ts_unix, bool persist);
  void maybe_maintain_locked();
  void write_snapshot_locked();
  void sweep_retention_locked();
  [[nodiscard]] std::string query_locked(const std::string& needle) const;
  [[nodiscard]] std::uint64_t now_locked() const { return clock_(); }
  [[nodiscard]] std::string segment_path(std::uint64_t win_start) const;

  std::string dir_;
  StoreOptions opts_;
  std::function<std::uint64_t()> clock_;

  mutable std::mutex mu_;
  std::map<std::string, Gauge> gauges_;  // key = sender_hex + '\x1f' + metric
  std::deque<Event> events_;             // bounded ring of recent events
  bool gauges_dirty_ = false;
  std::uint64_t last_maintenance_ = 0;

  std::unordered_set<std::string> seen_;  // msg_id (raw 16 bytes as string)
  std::deque<std::string> seen_order_;    // FIFO to bound seen_
};

}  // namespace tier::agent
