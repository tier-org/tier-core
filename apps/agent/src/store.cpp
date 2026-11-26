#include "store.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <utility>
#include <vector>

namespace tier::agent {
namespace {

namespace fs = std::filesystem;

constexpr char kSep = '\x1f';          // unit separator between sender and key
constexpr std::size_t kMaxEvents = 10000;
constexpr std::size_t kSnapshotEvents = 50;
constexpr std::size_t kMaxSeen = 20000;
constexpr const char* kSnapshot = "gauges.snap";
constexpr const char* kSnapshotTmp = "gauges.snap.tmp";
constexpr const char* kSegPrefix = "events-";
constexpr const char* kSegSuffix = ".log";

// Validate one UTF-8 sequence before including it in a JSON string.
std::size_t utf8_length(std::string_view text) {
  const auto lead = static_cast<unsigned char>(text.front());
  if (lead < 0xc2 || lead > 0xf4) return 0;
  const std::size_t length = lead < 0xe0 ? 2U : (lead < 0xf0 ? 3U : 4U);
  if (text.size() < length) return 0;
  const auto second = static_cast<unsigned char>(text[1]);
  if ((lead == 0xe0 && second < 0xa0) || (lead == 0xed && second >= 0xa0) ||
      (lead == 0xf0 && second < 0x90) || (lead == 0xf4 && second >= 0x90)) {
    return 0;
  }
  for (std::size_t i = 1; i < length; ++i) {
    if ((static_cast<unsigned char>(text[i]) & 0xc0U) != 0x80U) return 0;
  }
  return length;
}

void json_string(std::ostream& out, std::string_view text) {
  constexpr std::string_view hex = "0123456789abcdef";
  out << '"';
  while (!text.empty()) {
    const auto c = static_cast<unsigned char>(text.front());
    std::size_t length = 1;
    if (c == '"' || c == '\\') {
      out << '\\' << text.front();
    } else if (c < 0x20) {
      out << "\\u00" << hex[c >> 4] << hex[c & 0x0f];
    } else if (c < 0x80) {
      out << text.front();
    } else if (const std::size_t valid = utf8_length(text); valid != 0) {
      out << text.substr(0, valid);
      length = valid;
    } else {
      out << "\\ufffd";
    }
    text.remove_prefix(length);
  }
  out << '"';
}

// Persist/replay line: "<ts> <sender_hex> <kind> <key> <value...>". Key is
// assumed free of spaces (metric names are); value is the remainder of the line.
std::string encode_line(const std::string& sender, Kind kind,
                        const std::string& key, const std::string& value,
                        std::uint64_t ts) {
  std::ostringstream os;
  os << ts << ' ' << sender << ' ' << (kind == Kind::gauge ? "gauge" : "event")
     << ' ' << key << ' ' << value;
  return os.str();
}

// Parse one persisted line back into (sender, sample, ts). Returns false on a
// blank or malformed line.
bool decode_line(const std::string& line, std::string& sender, Sample& s,
                 std::uint64_t& ts) {
  if (line.empty()) return false;
  std::istringstream is(line);
  std::string kind;
  std::string key;
  if (!(is >> ts >> sender >> kind >> key)) return false;
  std::string value;
  std::getline(is, value);
  if (!value.empty() && value.front() == ' ') value.erase(0, 1);
  s.kind = (kind == "event") ? Kind::event : Kind::gauge;
  s.key = key;
  s.value = value;
  return true;
}

// If `name` is an event segment file ("events-<digits>.log"), return its window
// start; otherwise nullopt.
std::optional<std::uint64_t> segment_window(const std::string& name) {
  const std::string pre = kSegPrefix;
  const std::string suf = kSegSuffix;
  if (name.size() <= pre.size() + suf.size()) return std::nullopt;
  if (name.compare(0, pre.size(), pre) != 0) return std::nullopt;
  if (name.compare(name.size() - suf.size(), suf.size(), suf) != 0) {
    return std::nullopt;
  }
  const std::string mid =
      name.substr(pre.size(), name.size() - pre.size() - suf.size());
  if (mid.empty()) return std::nullopt;
  std::uint64_t win = 0;
  for (const char c : mid) {
    if (c < '0' || c > '9') return std::nullopt;
    win = win * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return win;
}

// Event segments in `dir`, sorted by window ascending.
std::vector<std::pair<std::uint64_t, fs::path>> list_segments(
    const std::string& dir) {
  std::vector<std::pair<std::uint64_t, fs::path>> segs;
  std::error_code ec;
  for (const auto& e : fs::directory_iterator(dir, ec)) {
    if (ec) break;
    if (!e.is_regular_file()) continue;
    const auto win = segment_window(e.path().filename().string());
    if (win) segs.emplace_back(*win, e.path());
  }
  std::sort(segs.begin(), segs.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  return segs;
}

}  // namespace

Store::Store(std::string dir, StoreOptions opts)
    : dir_(std::move(dir)),
      opts_(opts),
      clock_([] { return static_cast<std::uint64_t>(std::time(nullptr)); }) {
  load();
}

void Store::load() {
  last_maintenance_ = now_locked();
  if (dir_.empty()) return;  // in-memory only

  std::error_code ec;
  fs::create_directories(dir_, ec);

  const auto replay = [this](const fs::path& p) {
    std::ifstream in(p);
    std::string line;
    while (std::getline(in, line)) {
      std::string sender;
      Sample s;
      std::uint64_t ts = 0;
      if (decode_line(line, sender, s, ts)) {
        record(sender, s, ts, std::nullopt);
      }
    }
  };

  // Gauges from the snapshot, then events from each segment oldest-first (the
  // in-memory event ring bounds memory regardless of history on disk).
  const fs::path snap = fs::path(dir_) / kSnapshot;
  if (fs::exists(snap)) replay(snap);
  for (const auto& [win, path] : list_segments(dir_)) {
    (void)win;
    replay(path);
  }
}

bool Store::first_seen(const std::array<std::uint8_t, 16>& msg_id) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string k(reinterpret_cast<const char*>(msg_id.data()), msg_id.size());
  if (seen_.count(k) != 0) return false;
  seen_.insert(k);
  seen_order_.push_back(k);
  if (seen_order_.size() > kMaxSeen) {
    seen_.erase(seen_order_.front());
    seen_order_.pop_front();
  }
  return true;
}

std::string Store::segment_path(std::uint64_t win_start) const {
  return (fs::path(dir_) / (std::string(kSegPrefix) +
                            std::to_string(win_start) + kSegSuffix))
      .string();
}

void Store::record(const std::string& sender_hex, const Sample& s,
                   std::uint64_t ts_unix,
                   std::optional<std::uint64_t> received_unix) {
  if (s.kind == Kind::gauge) {
    gauges_[sender_hex + kSep + s.key] = Gauge{s.value, ts_unix, received_unix};
    if (received_unix) gauges_dirty_ = true;
    return;
  }
  events_.push_back(Event{sender_hex, s.key, s.value, ts_unix, received_unix});
  if (events_.size() > kMaxEvents) events_.pop_front();
  if (received_unix && !dir_.empty()) {
    const auto t = *received_unix;
    const std::uint64_t seg =
        opts_.segment_secs == 0 ? 0 : t - (t % opts_.segment_secs);
    std::ofstream out(segment_path(seg), std::ios::app);
    if (out) {
      out << encode_line(sender_hex, s.kind, s.key, s.value, ts_unix) << '\n';
    }
  }
}

void Store::apply(const std::string& sender_hex, const Envelope& env) {
  std::lock_guard<std::mutex> lk(mu_);
  const std::uint64_t received_unix = now_locked();
  for (const Sample& s : env.samples) {
    record(sender_hex, s, env.ts_unix, received_unix);
  }
  maybe_maintain_locked();
}

void Store::flush() {
  std::lock_guard<std::mutex> lk(mu_);
  if (dir_.empty()) return;
  if (gauges_dirty_) write_snapshot_locked();
  sweep_retention_locked();
  last_maintenance_ = now_locked();
}

void Store::maybe_maintain_locked() {
  if (dir_.empty()) return;
  const std::uint64_t t = now_locked();
  if (t - last_maintenance_ < opts_.snapshot_interval_secs) return;
  if (gauges_dirty_) write_snapshot_locked();
  sweep_retention_locked();
  last_maintenance_ = t;
}

void Store::write_snapshot_locked() {
  const fs::path tmp = fs::path(dir_) / kSnapshotTmp;
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) return;
    for (const auto& [k, g] : gauges_) {
      const auto sep = k.find(kSep);
      const std::string sender = k.substr(0, sep);
      const std::string key =
          sep == std::string::npos ? std::string{} : k.substr(sep + 1);
      out << encode_line(sender, Kind::gauge, key, g.value, g.ts_unix) << '\n';
    }
  }
  std::error_code ec;
  fs::rename(tmp, fs::path(dir_) / kSnapshot, ec);  // atomic replace
  if (!ec) gauges_dirty_ = false;
}

void Store::sweep_retention_locked() {
  if (dir_.empty()) return;
  auto segs = list_segments(dir_);
  if (segs.empty()) return;
  const std::uint64_t t = now_locked();

  // Time-based: drop any segment whose whole window is older than the cutoff.
  if (opts_.retention_secs != 0) {
    const std::uint64_t cutoff =
        t > opts_.retention_secs ? t - opts_.retention_secs : 0;
    std::vector<std::pair<std::uint64_t, fs::path>> kept;
    for (auto& [win, path] : segs) {
      if (win + opts_.segment_secs <= cutoff) {
        std::error_code ec;
        fs::remove(path, ec);
      } else {
        kept.emplace_back(win, std::move(path));
      }
    }
    segs = std::move(kept);
  }

  // Size-based: drop oldest segments until under the cap, but never the newest
  // (active) one - that is where current telemetry is still landing.
  if (opts_.max_bytes != 0 && segs.size() > 1) {
    std::uint64_t total = 0;
    std::vector<std::uint64_t> sizes(segs.size(), 0);
    for (std::size_t i = 0; i < segs.size(); ++i) {
      std::error_code ec;
      sizes[i] = static_cast<std::uint64_t>(fs::file_size(segs[i].second, ec));
      if (!ec) total += sizes[i];
    }
    std::size_t i = 0;
    while (total > opts_.max_bytes && i + 1 < segs.size()) {
      std::error_code ec;
      fs::remove(segs[i].second, ec);
      total -= sizes[i];
      ++i;
    }
  }
}

std::string Store::query(const std::string& needle) const {
  std::lock_guard<std::mutex> lk(mu_);
  return query_locked(needle);
}

std::string Store::snapshot_json(std::string_view sender) const {
  std::lock_guard<std::mutex> lk(mu_);
  struct Node {
    std::optional<std::uint64_t> received_unix;
    std::vector<std::pair<std::string_view, const Gauge*>> gauges;
  };
  std::map<std::string_view, Node> nodes;
  for (const auto& [label, gauge] : gauges_) {
    const std::string_view name(label);
    const auto sep = name.find(kSep);
    const auto id = name.substr(0, sep);
    if (!sender.empty() && id != sender) continue;
    auto& node = nodes[id];
    node.received_unix = std::max(node.received_unix, gauge.received_unix);
    node.gauges.emplace_back(name.substr(sep + 1), &gauge);
  }
  std::vector<const Event*> events;
  for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
    if (!sender.empty() && it->sender != sender) continue;
    auto& node = nodes[it->sender];
    node.received_unix = std::max(node.received_unix, it->received_unix);
    if (events.size() < kSnapshotEvents) events.push_back(&*it);
  }

  std::ostringstream out;
  out << "{\"version\":1,\"nodes\":[";
  const char* separator = "";
  for (const auto& [id, node] : nodes) {
    out << std::exchange(separator, ",") << "{\"sender\":";
    json_string(out, id);
    out << ",\"received_unix\":";
    if (node.received_unix) {
      out << *node.received_unix;
    } else {
      out << "null";
    }
    out << ",\"gauges\":[";
    const char* gauge_separator = "";
    for (const auto& [key, gauge] : node.gauges) {
      out << std::exchange(gauge_separator, ",") << "{\"key\":";
      json_string(out, key);
      out << ",\"value\":";
      json_string(out, gauge->value);
      out << ",\"ts_unix\":" << gauge->ts_unix << '}';
    }
    out << "]}";
  }
  out << "],\"events\":[";
  separator = "";
  for (const Event* event : events) {
    out << std::exchange(separator, ",") << "{\"sender\":";
    json_string(out, event->sender);
    out << ",\"key\":";
    json_string(out, event->key);
    out << ",\"value\":";
    json_string(out, event->value);
    out << ",\"ts_unix\":" << event->ts_unix << '}';
  }
  out << "]}\n";
  return out.str();
}

std::string Store::query_locked(const std::string& needle) const {
  const auto keep = [&needle](const std::string& label) {
    return needle.empty() || label.find(needle) != std::string::npos;
  };

  // Filter first so the printed counts reflect what is shown.
  std::vector<std::pair<std::string, const Gauge*>> gsel;
  for (const auto& [k, g] : gauges_) {
    std::string pretty = k;
    const auto sep = pretty.find(kSep);
    if (sep != std::string::npos) pretty[sep] = '/';
    if (keep(pretty)) gsel.emplace_back(std::move(pretty), &g);
  }
  std::vector<const Event*> esel;
  for (const Event& e : events_) {
    if (keep(e.sender + '/' + e.key)) esel.push_back(&e);
  }

  std::ostringstream os;
  os << "# gauges (" << gsel.size() << ")\n";
  for (const auto& [pretty, g] : gsel) {
    os << g->ts_unix << ' ' << pretty << ' ' << g->value << '\n';
  }
  os << "# events (" << esel.size() << ")\n";
  for (const Event* e : esel) {
    os << e->ts_unix << ' ' << e->sender << '/' << e->key << ' ' << e->value
       << '\n';
  }
  return os.str();
}

std::size_t Store::gauge_count() const {
  std::lock_guard<std::mutex> lk(mu_);
  return gauges_.size();
}

std::size_t Store::event_count() const {
  std::lock_guard<std::mutex> lk(mu_);
  return events_.size();
}

}  // namespace tier::agent
