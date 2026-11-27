#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "envelope.hpp"

namespace tier::agent {

// Agent-side batching buffer. Between flushes it accumulates samples: gauges
// collapse to the newest value per key (only the latest reading matters, so a
// hot gauge does not inflate the batch), while events are all retained in order.
// drain() produces one Envelope and clears the buffer. Pure and single-threaded;
// the caller serializes access.
class Batcher {
 public:
  // `max_samples` is the soft cap at which full() reports true so the caller can
  // flush early (distinct gauge keys + events). Zero is treated as one.
  explicit Batcher(std::size_t max_samples)
      : max_(std::clamp(max_samples == 0 ? 1 : max_samples,
                        std::size_t{1}, kMaxSamples)) {}

  // Buffer one sample. A gauge overwrites any pending value for its key; an
  // event is appended.
  void add(const Sample& s);

  [[nodiscard]] std::size_t size() const {
    return gauges_.size() + events_.size();
  }
  [[nodiscard]] bool empty() const {
    return gauges_.empty() && events_.empty();
  }
  [[nodiscard]] bool full() const { return size() >= max_; }

  // Move the buffered samples into an Envelope (gauges first, then events in
  // arrival order) stamped with `seq`/`ts_unix`, and clear the buffer.
  [[nodiscard]] Envelope drain(std::uint64_t seq, std::uint64_t ts_unix);

 private:
  std::size_t max_;
  std::map<std::string, std::string> gauges_;  // key -> latest value
  std::vector<Sample> events_;                 // append-only, arrival order
};

}  // namespace tier::agent
