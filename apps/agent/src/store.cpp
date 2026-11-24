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
constexpr std::size_t kMaxSeen = 20000;
constexpr const char* kSnapshot = "gauges.snap";
constexpr const char* kSnapshotTmp = "gauges.snap.tmp";
constexpr const char* kSegPrefix = "events-";
constexpr const char* kSegSuffix = ".log";

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
        record(sender, s, ts, /*persist=*/false);
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
                   std::uint64_t ts_unix, bool persist) {
  if (s.kind == Kind::gauge) {
    gauges_[sender_hex + kSep + s.key] = Gauge{s.value, ts_unix};
    if (persist) gauges_dirty_ = true;  // snapshotted later, not appended
    return;
  }
  events_.push_back(Event{sender_hex, s.key, s.value, ts_unix});
  if (events_.size() > kMaxEvents) events_.pop_front();
  if (persist && !dir_.empty()) {
    const std::uint64_t t = now_locked();
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
  for (const Sample& s : env.samples) {
    record(sender_hex, s, env.ts_unix, /*persist=*/true);
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
