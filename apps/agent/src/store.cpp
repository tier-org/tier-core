#include "store.hpp"

#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

namespace tier::agent {
namespace {

constexpr char kSep = '\x1f';          // unit separator between sender and key
constexpr std::size_t kMaxEvents = 10000;
constexpr std::size_t kMaxSeen = 20000;

// Persist/replay line: "<ts> <sender_hex> <kind> <key> <value...>". Key is
// assumed free of spaces (metric names are); value is the remainder of the line.
std::string encode_line(const std::string& sender, const Sample& s,
                        std::uint64_t ts) {
  std::ostringstream os;
  os << ts << ' ' << sender << ' '
     << (s.kind == Kind::gauge ? "gauge" : "event") << ' ' << s.key << ' '
     << s.value;
  return os.str();
}

}  // namespace

Store::Store(std::string path) : path_(std::move(path)) {
  if (path_.empty()) return;
  std::ifstream in(path_);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::istringstream is(line);
    std::uint64_t ts = 0;
    std::string sender;
    std::string kind;
    std::string key;
    if (!(is >> ts >> sender >> kind >> key)) continue;
    std::string value;
    std::getline(is, value);
    if (!value.empty() && value.front() == ' ') value.erase(0, 1);
    Sample s;
    s.kind = (kind == "event") ? Kind::event : Kind::gauge;
    s.key = key;
    s.value = value;
    record(sender, s, ts, /*persist=*/false);  // replay: do not rewrite the log
  }
}

bool Store::first_seen(const std::array<std::uint8_t, 16>& msg_id) {
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

void Store::record(const std::string& sender_hex, const Sample& s,
                   std::uint64_t ts_unix, bool persist) {
  if (s.kind == Kind::gauge) {
    gauges_[sender_hex + kSep + s.key] = Gauge{s.value, ts_unix};
  } else {
    events_.push_back(Event{sender_hex, s.key, s.value, ts_unix});
    if (events_.size() > kMaxEvents) events_.pop_front();
  }
  if (persist && !path_.empty()) {
    std::ofstream out(path_, std::ios::app);
    if (out) out << encode_line(sender_hex, s, ts_unix) << '\n';
  }
}

void Store::apply(const std::string& sender_hex, const Envelope& env) {
  for (const Sample& s : env.samples) {
    record(sender_hex, s, env.ts_unix, /*persist=*/true);
  }
}

std::string Store::query(const std::string& needle) const {
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

}  // namespace tier::agent
