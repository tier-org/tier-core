#ifndef TIER_NODE_CONFIG_HPP
#define TIER_NODE_CONFIG_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Operator configuration read from the node config file (/etc/tier/tierd.toml
// by default, or $TIER_CONFIG). The file is a small, dependency-free subset of
// TOML - enough for the flat operator knobs today, and a strict subset of real
// TOML so the format does not have to change if a parser library is adopted
// later. Supported syntax, one key per line:
//
//   # a comment (also allowed after a value)
//   network = "testnet"            # quoted or bare scalar string
//   version_range = "1.4.0,1.5.0"
//   roles = ["validator", "keeper"]  # inline array of strings
//   seeds = ["[fd00::2]:7777", "10.0.0.2:7777"]
//
// Every field is optional: an absent key leaves that knob to its other source.
// The daemon layers sources as CLI > environment > this file > baked default,
// so the file is the canonical home and environment variables override it.
//
// Values are kept as raw strings; the daemon interprets roles and the version
// range through the same code paths as the matching environment variables, so a
// file value and an env value mean exactly the same thing.
namespace tier::node {

struct Config {
  std::optional<std::string> network;
  std::optional<std::vector<std::string>> roles;
  std::optional<std::vector<std::string>> seeds;
  std::optional<std::string> version_range;
};

namespace detail {

inline std::string_view trim(std::string_view s) {
  const auto is_space = [](char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  while (!s.empty() && is_space(s.front())) {
    s.remove_prefix(1);
  }
  while (!s.empty() && is_space(s.back())) {
    s.remove_suffix(1);
  }
  return s;
}

// Drop an unquoted trailing "# comment" from a value, leaving quoted '#' alone.
inline std::string_view strip_comment(std::string_view s) {
  bool in_quote = false;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '"') {
      in_quote = !in_quote;
    } else if (s[i] == '#' && !in_quote) {
      return trim(s.substr(0, i));
    }
  }
  return s;
}

// A single scalar: a "quoted" string (returning its contents) or a bare token.
// Sets ok=false if an opening quote has no closing quote.
inline std::string parse_scalar(std::string_view v, bool& ok) {
  ok = true;
  v = trim(v);
  if (v.size() >= 1 && v.front() == '"') {
    if (v.size() < 2 || v.back() != '"') {
      ok = false;
      return {};
    }
    return std::string(v.substr(1, v.size() - 2));
  }
  return std::string(v);
}

// Split the inside of "[...]" on commas that are not inside quotes.
inline std::optional<std::vector<std::string>> parse_array(std::string_view v) {
  v = trim(v);
  if (v.size() < 2 || v.front() != '[' || v.back() != ']') {
    return std::nullopt;
  }
  const std::string_view inner = trim(v.substr(1, v.size() - 2));
  std::vector<std::string> out;
  if (inner.empty()) {
    return out;  // "[]" is a valid empty array
  }
  std::size_t start = 0;
  bool in_quote = false;
  const auto push = [&](std::string_view elem) -> bool {
    elem = trim(elem);
    if (elem.empty()) {
      return true;  // tolerate a trailing comma
    }
    bool ok = false;
    std::string s = parse_scalar(elem, ok);
    if (!ok) {
      return false;
    }
    out.push_back(std::move(s));
    return true;
  };
  for (std::size_t i = 0; i < inner.size(); ++i) {
    if (inner[i] == '"') {
      in_quote = !in_quote;
    } else if (inner[i] == ',' && !in_quote) {
      if (!push(inner.substr(start, i - start))) {
        return std::nullopt;
      }
      start = i + 1;
    }
  }
  if (!push(inner.substr(start))) {
    return std::nullopt;
  }
  return out;
}

}  // namespace detail

// Parse the config text. On success returns the Config; on a malformed line or
// an unknown/duplicate key returns std::nullopt and sets `error` to a one-line,
// 1-based diagnostic.
inline std::optional<Config> parse_config(std::string_view text,
                                          std::string& error) {
  Config cfg;
  std::size_t line_no = 0;
  std::size_t pos = 0;
  const auto fail = [&](const std::string& msg) -> std::optional<Config> {
    error = "line " + std::to_string(line_no) + ": " + msg;
    return std::nullopt;
  };

  while (pos <= text.size()) {
    const std::size_t nl = text.find('\n', pos);
    const std::string_view raw =
        text.substr(pos, nl == std::string_view::npos ? std::string_view::npos
                                                       : nl - pos);
    pos = (nl == std::string_view::npos) ? text.size() + 1 : nl + 1;
    ++line_no;

    const std::string_view line = detail::trim(raw);
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) {
      return fail("expected key = value");
    }
    const std::string_view key = detail::trim(line.substr(0, eq));
    const std::string_view value =
        detail::strip_comment(detail::trim(line.substr(eq + 1)));
    if (key.empty()) {
      return fail("empty key");
    }
    if (value.empty()) {
      return fail("missing value");
    }

    const bool is_array = value.front() == '[';
    const auto want_scalar = [&](std::optional<std::string>& field)
        -> std::optional<Config> {
      if (field.has_value()) {
        return fail("duplicate key '" + std::string(key) + "'");
      }
      if (is_array) {
        return fail("key '" + std::string(key) + "' expects a string");
      }
      bool ok = false;
      std::string s = detail::parse_scalar(value, ok);
      if (!ok) {
        return fail("unterminated string");
      }
      field = std::move(s);
      return Config{};  // sentinel: success (ignored)
    };
    const auto want_array = [&](std::optional<std::vector<std::string>>& field)
        -> std::optional<Config> {
      if (field.has_value()) {
        return fail("duplicate key '" + std::string(key) + "'");
      }
      if (is_array) {
        auto arr = detail::parse_array(value);
        if (!arr) {
          return fail("malformed array");
        }
        field = std::move(*arr);
      } else {
        // A bare scalar is accepted as a single-element list, so
        // `roles = "transmitter"` works as well as `roles = ["transmitter"]`.
        bool ok = false;
        std::string s = detail::parse_scalar(value, ok);
        if (!ok) {
          return fail("unterminated string");
        }
        field = std::vector<std::string>{std::move(s)};
      }
      return Config{};
    };

    std::optional<Config> err;
    if (key == "network") {
      err = want_scalar(cfg.network);
    } else if (key == "version_range") {
      err = want_scalar(cfg.version_range);
    } else if (key == "roles") {
      err = want_array(cfg.roles);
    } else if (key == "seeds") {
      err = want_array(cfg.seeds);
    } else {
      return fail("unknown key '" + std::string(key) + "'");
    }
    if (!err) {
      return std::nullopt;  // a helper already set `error`
    }
  }
  return cfg;
}

}  // namespace tier::node

#endif  // TIER_NODE_CONFIG_HPP
