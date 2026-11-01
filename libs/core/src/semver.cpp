#include "tier/core/semver.hpp"

#include <cctype>
#include <limits>

namespace tier::core {
namespace {

// Parse a run of ASCII digits as a uint64, rejecting an empty string or an
// overflow. Returns false on either; the core components use this.
bool parse_u64(std::string_view s, std::uint64_t& out) noexcept {
  if (s.empty()) {
    return false;
  }
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
    const auto digit = static_cast<std::uint64_t>(c - '0');
    if (v > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      return false;  // overflow
    }
    v = v * 10U + digit;
  }
  out = v;
  return true;
}

// Is every character of a pre-release identifier set allowed? SemVer allows
// [0-9A-Za-z-] and dot-separated identifiers; we accept the same and leave
// per-identifier emptiness to the caller.
bool is_prerelease_charset(std::string_view s) noexcept {
  for (const char c : s) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') || c == '.' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

// Does a pre-release string have an empty dot-separated identifier (leading,
// trailing or doubled dot)? Those are malformed.
bool has_empty_identifier(std::string_view s) noexcept {
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == '.') {
      if (i == start) {
        return true;  // empty segment
      }
      start = i + 1;
    }
  }
  return false;
}

bool is_numeric(std::string_view s) noexcept {
  for (const char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  return !s.empty();
}

// Compare two pre-release identifier lists per SemVer rule 11.4: numeric
// identifiers compare numerically and rank below non-numeric; otherwise ASCII;
// a longer list wins when a shorter is its prefix.
int compare_prerelease(std::string_view a, std::string_view b) noexcept {
  std::size_t ai = 0;
  std::size_t bi = 0;
  while (ai < a.size() && bi < b.size()) {
    const std::size_t adot = a.find('.', ai);
    const std::size_t bdot = b.find('.', bi);
    const std::string_view at =
        a.substr(ai, (adot == std::string_view::npos ? a.size() : adot) - ai);
    const std::string_view bt =
        b.substr(bi, (bdot == std::string_view::npos ? b.size() : bdot) - bi);

    const bool an = is_numeric(at);
    const bool bn = is_numeric(bt);
    if (an && bn) {
      std::uint64_t av = 0;
      std::uint64_t bv = 0;
      // Already validated as numeric; overflow is not meaningful for ordering
      // of sane versions, so parse best-effort and fall back to length/ASCII.
      if (parse_u64(at, av) && parse_u64(bt, bv)) {
        if (av != bv) {
          return av < bv ? -1 : 1;
        }
      }
    } else if (an != bn) {
      return an ? -1 : 1;  // numeric ranks below non-numeric
    } else {
      const int c = at.compare(bt);
      if (c != 0) {
        return c < 0 ? -1 : 1;
      }
    }
    ai = (adot == std::string_view::npos ? a.size() : adot + 1);
    bi = (bdot == std::string_view::npos ? b.size() : bdot + 1);
  }
  const bool a_more = ai < a.size();
  const bool b_more = bi < b.size();
  if (a_more == b_more) {
    return 0;
  }
  return a_more ? 1 : -1;  // the list with more identifiers is greater
}

}  // namespace

std::optional<SemVer> parse_semver(std::string_view in) {
  if (in.empty()) {
    return std::nullopt;
  }

  // Strip build metadata ("+..."): ignored by precedence, but must be non-empty
  // when the '+' is present.
  std::string_view core_and_pre = in;
  if (const std::size_t plus = in.find('+'); plus != std::string_view::npos) {
    if (plus + 1 == in.size()) {
      return std::nullopt;  // trailing '+' with no build metadata
    }
    core_and_pre = in.substr(0, plus);
  }

  // Split off the pre-release ("-...").
  std::string_view core = core_and_pre;
  std::string_view pre;
  if (const std::size_t dash = core_and_pre.find('-');
      dash != std::string_view::npos) {
    pre = core_and_pre.substr(dash + 1);
    core = core_and_pre.substr(0, dash);
    if (pre.empty() || !is_prerelease_charset(pre) || has_empty_identifier(pre)) {
      return std::nullopt;
    }
  }

  // Core: exactly three numeric components.
  SemVer v;
  const std::size_t d1 = core.find('.');
  if (d1 == std::string_view::npos) {
    return std::nullopt;
  }
  const std::size_t d2 = core.find('.', d1 + 1);
  if (d2 == std::string_view::npos) {
    return std::nullopt;
  }
  if (core.find('.', d2 + 1) != std::string_view::npos) {
    return std::nullopt;  // a fourth component
  }
  if (!parse_u64(core.substr(0, d1), v.major) ||
      !parse_u64(core.substr(d1 + 1, d2 - d1 - 1), v.minor) ||
      !parse_u64(core.substr(d2 + 1), v.patch)) {
    return std::nullopt;
  }
  v.prerelease = std::string(pre);
  return v;
}

int compare_semver(const SemVer& a, const SemVer& b) noexcept {
  if (a.major != b.major) {
    return a.major < b.major ? -1 : 1;
  }
  if (a.minor != b.minor) {
    return a.minor < b.minor ? -1 : 1;
  }
  if (a.patch != b.patch) {
    return a.patch < b.patch ? -1 : 1;
  }
  // Equal core: a version with a pre-release is lower than one without.
  const bool ap = !a.prerelease.empty();
  const bool bp = !b.prerelease.empty();
  if (ap != bp) {
    return ap ? -1 : 1;
  }
  if (!ap) {
    return 0;  // both are plain releases
  }
  return compare_prerelease(a.prerelease, b.prerelease);
}

}  // namespace tier::core
