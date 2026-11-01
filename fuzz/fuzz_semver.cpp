#include <cstddef>
#include <cstdint>
#include <string_view>

#include "tier/core/version_range.hpp"

// A peer's version string arrives over gossip (PeerInfo::version) and is parsed
// by version_admitted -> parse_semver, and TIER_VERSION_RANGE is parsed into a
// range; both run on untrusted/operator input and must never crash. Split the
// input so one buffer feeds the range and the rest the version it judges.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view in(reinterpret_cast<const char*>(data), size);
  const std::size_t cut = size / 2;
  const std::string_view spec = in.substr(0, cut);
  const std::string_view version = in.substr(cut);

  static_cast<void>(tier::core::parse_semver(version));
  const auto range = tier::core::parse_version_range(spec);
  if (range) {
    static_cast<void>(tier::core::version_admitted(*range, version));
  }
  return 0;
}
