#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// tier-agent wire envelope. One message carries a batch of samples shipped
// from an agent to a collector. The network treats the whole thing as an opaque
// sealed payload; this codec lives entirely at the application layer, so the
// tier core/transport learns nothing about telemetry semantics.
//
// A sample is either a gauge (rewritable, last-value-wins by key - current CPU,
// memory, unit state) or an event (append-only history). The collector keys
// gauges by (sender_user, key) and overwrites; it appends events. Ordering and
// de-duplication use the message's seq/ts here plus the network-provided msg_id.
namespace tier::agent {

enum class Kind : std::uint8_t {
  gauge = 0,  // rewritable: last value for this key wins
  event = 1,  // append-only: kept as history
};

struct Sample {
  Kind kind = Kind::gauge;
  std::string key;    // metric name, e.g. "cpu.load" or "unit.sshd"
  std::string value;  // opaque UTF-8 value (number or token); collector-defined
};

struct Envelope {
  std::uint64_t seq = 0;       // per-agent monotonically increasing counter
  std::uint64_t ts_unix = 0;   // agent wall-clock at capture (seconds)
  std::vector<Sample> samples;
};

// Wire format (all integers big-endian):
//   ["TM"][ver:1=1][seq:8][ts_unix:8][count:2]
//   count x ( [kind:1][klen:2][key][vlen:4][value] )
[[nodiscard]] std::vector<std::uint8_t> encode(const Envelope& env);

// Decode a full envelope. std::nullopt on a bad magic/version, truncation,
// an unknown kind, an oversize field, or trailing bytes.
[[nodiscard]] std::optional<Envelope> decode(const std::uint8_t* data,
                                             std::size_t n);

}  // namespace tier::agent
