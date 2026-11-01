#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tier::core {

// A parsed semantic version (SemVer 2.0.0): a numeric MAJOR.MINOR.PATCH core
// with an optional pre-release suffix. Only what version pinning needs.
//
// Precedence (see compare_semver) follows the spec: compare the numeric core,
// then a version with a pre-release ranks BELOW the same core without one
// (1.4.0-rc.1 < 1.4.0). Build metadata ("+..."), if present, is parsed off and
// ignored, as the spec requires.
struct SemVer {
  std::uint64_t major = 0;
  std::uint64_t minor = 0;
  std::uint64_t patch = 0;
  std::string prerelease;  // the "rc.1" of "1.4.0-rc.1"; empty when absent
};

// Parse "MAJOR.MINOR.PATCH" with an optional "-prerelease" and "+build" suffix.
// Returns std::nullopt on anything malformed: a missing or non-numeric core
// component, a core number that overflows, or an empty pre-release/build when
// its separator is present. The input is not trimmed; callers strip whitespace.
[[nodiscard]] std::optional<SemVer> parse_semver(std::string_view in);

// SemVer precedence: negative if a < b, zero if equal, positive if a > b.
[[nodiscard]] int compare_semver(const SemVer& a, const SemVer& b) noexcept;

}  // namespace tier::core
