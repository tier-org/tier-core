#include "config.hpp"

#include <cctype>
#include <sstream>

#include "tier/core/address.hpp"

namespace tier::agent {
namespace {

std::string trim(const std::string& s) {
  std::size_t a = 0;
  std::size_t b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// Strip surrounding double quotes if present.
std::string unquote(const std::string& s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
    return s.substr(1, s.size() - 2);
  }
  return s;
}

// Split a TOML array literal [ "a", "b" ] into its string elements.
std::vector<std::string> parse_array(const std::string& v) {
  std::vector<std::string> out;
  const std::string inner = trim(v.substr(1, v.size() - 2));  // drop [ ]
  std::string cur;
  std::stringstream ss(inner);
  while (std::getline(ss, cur, ',')) {
    const std::string e = unquote(trim(cur));
    if (!e.empty()) out.push_back(e);
  }
  return out;
}

bool to_peer(const std::string& addr, tier::core::PeerId& out, std::string& err) {
  const auto id = tier::core::id_from_address(addr);
  if (!id) {
    err = "invalid tier address: " + addr;
    return false;
  }
  out = *id;
  return true;
}

// Parse a non-negative decimal into a u32, with range checking.
bool to_u32(const std::string& v, std::uint32_t& out, std::string& err) {
  if (v.empty()) {
    err = "expected a number, got empty value";
    return false;
  }
  std::uint64_t acc = 0;
  for (const char c : v) {
    if (c < '0' || c > '9') {
      err = "not a non-negative integer: " + v;
      return false;
    }
    acc = acc * 10 + static_cast<std::uint64_t>(c - '0');
    if (acc > 0xFFFFFFFFULL) {
      err = "number out of range: " + v;
      return false;
    }
  }
  out = static_cast<std::uint32_t>(acc);
  return true;
}

// Split a value into its leading decimal digits and a trailing unit suffix.
bool split_number_unit(const std::string& v, std::uint64_t& num,
                       std::string& unit, std::string& err) {
  std::size_t i = 0;
  std::uint64_t acc = 0;
  while (i < v.size() && v[i] >= '0' && v[i] <= '9') {
    acc = acc * 10 + static_cast<std::uint64_t>(v[i] - '0');
    ++i;
  }
  if (i == 0) {
    err = "expected a number: " + v;
    return false;
  }
  num = acc;
  unit = trim(v.substr(i));
  return true;
}

// Parse a duration like "7d", "24h", "30m", "90s"; a bare number is seconds.
bool to_duration(const std::string& v, std::uint64_t& out, std::string& err) {
  std::uint64_t num = 0;
  std::string unit;
  if (!split_number_unit(v, num, unit, err)) return false;
  std::uint64_t mult = 1;
  if (unit.empty() || unit == "s") mult = 1;
  else if (unit == "m") mult = 60;
  else if (unit == "h") mult = 3600;
  else if (unit == "d") mult = 86400;
  else {
    err = "unknown duration unit (use s|m|h|d): " + v;
    return false;
  }
  out = num * mult;
  return true;
}

// Parse a byte size like "2GB", "512MB", "64KB"; a bare number is bytes.
bool to_size(const std::string& v, std::uint64_t& out, std::string& err) {
  std::uint64_t num = 0;
  std::string unit;
  if (!split_number_unit(v, num, unit, err)) return false;
  std::uint64_t mult = 1;
  if (unit.empty() || unit == "B") mult = 1;
  else if (unit == "KB" || unit == "K") mult = 1024ULL;
  else if (unit == "MB" || unit == "M") mult = 1024ULL * 1024;
  else if (unit == "GB" || unit == "G") mult = 1024ULL * 1024 * 1024;
  else {
    err = "unknown size unit (use B|KB|MB|GB): " + v;
    return false;
  }
  out = num * mult;
  return true;
}

}  // namespace

std::optional<Config> parse_config(const std::string& text, std::string& err) {
  Config cfg;
  bool role_set = false;
  std::string section;
  std::stringstream ss(text);
  std::string raw;
  while (std::getline(ss, raw, '\n')) {
    std::string line = trim(raw);
    if (line.empty() || line[0] == '#') continue;
    if (line.front() == '[' && line.back() == ']') {
      section = trim(line.substr(1, line.size() - 2));
      continue;
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      err = "expected key = value: " + line;
      return std::nullopt;
    }
    const std::string key = trim(line.substr(0, eq));
    const std::string valraw = trim(line.substr(eq + 1));
    const std::string val = unquote(valraw);

    if (section.empty()) {
      if (key == "role") {
        if (val == "agent") cfg.role = Role::agent;
        else if (val == "collector") cfg.role = Role::collector;
        else if (val == "both") cfg.role = Role::both;
        else { err = "role must be agent|collector|both"; return std::nullopt; }
        role_set = true;
      } else if (key == "admin_socket") {
        cfg.admin_socket = val;
      } else if (key == "seed_file") {
        cfg.seed_file = val;
      } else {
        err = "unknown top-level key: " + key;
        return std::nullopt;
      }
    } else if (section == "agent") {
      if (key == "collector") {
        if (!to_peer(val, cfg.collector, err)) return std::nullopt;
        cfg.has_collector = true;
      } else if (key == "interval") {
        if (!to_u32(val, cfg.interval_secs, err)) return std::nullopt;
        if (cfg.interval_secs == 0) {
          err = "interval must be >= 1";
          return std::nullopt;
        }
      } else if (key == "max_batch") {
        if (!to_u32(val, cfg.max_batch, err)) return std::nullopt;
        if (cfg.max_batch == 0) {
          err = "max_batch must be >= 1";
          return std::nullopt;
        }
      } else if (key == "exec") {
        cfg.exec = val;
      } else {
        err = "unknown [agent] key: " + key;
        return std::nullopt;
      }
    } else if (section == "collector") {
      if (key == "store") {
        cfg.store_path = val;
      } else if (key == "retention") {
        if (!to_duration(val, cfg.retention_secs, err)) return std::nullopt;
      } else if (key == "max_bytes") {
        if (!to_size(val, cfg.max_bytes, err)) return std::nullopt;
      } else if (key == "snapshot_interval") {
        std::uint64_t secs = 0;
        if (!to_duration(val, secs, err)) return std::nullopt;
        if (secs == 0 || secs > 0xFFFFFFFFULL) {
          err = "snapshot_interval out of range";
          return std::nullopt;
        }
        cfg.snapshot_interval_secs = static_cast<std::uint32_t>(secs);
      } else if (key == "query_socket") {
        cfg.query_socket = val;
      } else if (key == "persistence") {
        cfg.keeper_persistence = (val == "keeper");
      } else if (key == "accept_from") {
        if (valraw.empty() || valraw.front() != '[') {
          err = "accept_from must be an array";
          return std::nullopt;
        }
        for (const auto& a : parse_array(valraw)) {
          tier::core::PeerId p{};
          if (!to_peer(a, p, err)) return std::nullopt;
          cfg.accept_from.push_back(p);
        }
      } else {
        err = "unknown [collector] key: " + key;
        return std::nullopt;
      }
    } else {
      err = "unknown section: [" + section + "]";
      return std::nullopt;
    }
  }

  if (!role_set) {
    err = "missing required 'role'";
    return std::nullopt;
  }
  if ((cfg.role == Role::agent || cfg.role == Role::both) && !cfg.has_collector) {
    err = "agent role requires [agent] collector = \"<address>\"";
    return std::nullopt;
  }
  return cfg;
}

std::optional<Sample> parse_sample_line(const std::string& line) {
  const std::string s = trim(line);
  if (s.empty() || s[0] == '#') return std::nullopt;
  const auto sp1 = s.find(' ');
  if (sp1 == std::string::npos) return std::nullopt;
  const std::string kind = s.substr(0, sp1);
  const std::string rest = trim(s.substr(sp1 + 1));
  const auto sp2 = rest.find(' ');
  if (sp2 == std::string::npos) return std::nullopt;

  Sample out;
  if (kind == "gauge" || kind == "g") out.kind = Kind::gauge;
  else if (kind == "event" || kind == "e") out.kind = Kind::event;
  else return std::nullopt;
  out.key = rest.substr(0, sp2);
  out.value = rest.substr(sp2 + 1);  // may contain spaces
  if (out.key.empty()) return std::nullopt;
  return out;
}

}  // namespace tier::agent
