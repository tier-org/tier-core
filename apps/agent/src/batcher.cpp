#include "batcher.hpp"

#include <utility>

namespace tier::agent {

void Batcher::add(const Sample& s) {
  if (s.kind == Kind::gauge) {
    gauges_[s.key] = s.value;  // last-value-wins within the batch
  } else {
    events_.push_back(s);
  }
}

Envelope Batcher::drain(std::uint64_t seq, std::uint64_t ts_unix) {
  Envelope env;
  env.seq = seq;
  env.ts_unix = ts_unix;
  env.samples.reserve(gauges_.size() + events_.size());
  for (const auto& [key, value] : gauges_) {
    env.samples.push_back(Sample{Kind::gauge, key, value});
  }
  for (auto& e : events_) {
    env.samples.push_back(std::move(e));
  }
  gauges_.clear();
  events_.clear();
  return env;
}

}  // namespace tier::agent
