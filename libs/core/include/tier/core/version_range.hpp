#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tier/core/semver.hpp"

namespace tier::core {

// A per-network software-version policy: the window of versions a node will
// participate with on a given network. The lower bound is inclusive, the upper
// bound EXCLUSIVE, so "1.4.0,1.5.0" admits every 1.4.x and rejects 1.5.0 - the
// pessimistic "pin the minor, accept the patches" window. Either bound may be
// absent (open on that side); both absent means unconstrained.
//
// This is a cluster-governance knob, NOT a security boundary and NOT wire
// protocol: a peer's version is self-reported over gossip, so the range gates
// honest misconfiguration and lets governance freeze or retire versions, while
// hard incompatibility between builds that genuinely cannot interoperate is a
// separate concern (the network is isolated at the handshake via its ALPN
// token). The range itself is never sent on the wire - each node applies its
// own, resolved from the baked per-network default and the TIER_VERSION_RANGE
// override.
struct VersionRange {
  std::optional<SemVer> min;  // inclusive lower bound; absent = open below
  std::optional<SemVer> max;  // exclusive upper bound; absent = open above

  [[nodiscard]] bool unconstrained() const noexcept { return !min && !max; }

  // Is `v` within the window: min (if set) <= v < max (if set).
  [[nodiscard]] bool contains(const SemVer& v) const noexcept;
};

// Parse a range spec "min,max" (exactly one comma): each side a semver or empty
// for an open bound. Examples:
//   "1.4.0,1.5.0" -> [1.4.0, 1.5.0)      ""      -> unconstrained
//   "1.4.0,"      -> [1.4.0, +inf)       ","     -> unconstrained
//   ",2.0.0"      -> (-inf, 2.0.0)
// Surrounding whitespace on each bound is trimmed. Returns std::nullopt if a
// present bound is not valid semver, the comma is missing from a non-empty
// spec, or the window is empty (max <= min) - all operator configuration
// errors worth failing on rather than silently admitting nothing.
[[nodiscard]] std::optional<VersionRange> parse_version_range(
    std::string_view spec);

// Would a peer advertising `version` be admitted under `range`? An unconstrained
// range admits everything. An empty or unparseable version is admitted
// (lenient: a peer too old to advertise one, or garbage, cannot be judged, and
// kicking it would partition a mixed fleet). Only a well-formed version outside
// the window is refused.
[[nodiscard]] bool version_admitted(const VersionRange& range,
                                    std::string_view version);

// The compatibility range baked in for a network. The source of truth is the
// per-network files in the top-level networks/ directory, compiled into the
// binary at build time (never read at runtime). A network with no file - every
// private network - is unconstrained, and the TIER_VERSION_RANGE override then
// drives the knob.
[[nodiscard]] VersionRange network_version_range(std::string_view network);

// One baked public network and its resolved window.
struct NetworkPolicyInfo {
  std::string name;
  VersionRange range;
};

// All public networks baked into this binary (from networks/), in file order.
// Backs the `tierd networks` diagnostic.
[[nodiscard]] std::vector<NetworkPolicyInfo> baked_networks();

// Validate the baked table: every network name is well-formed and its
// version_range parses. Returns true, else false with *error (if non-null) set
// to the first problem. Used as a build gate so a malformed networks/ file
// cannot ship (see tests).
[[nodiscard]] bool validate_baked_networks(std::string* error);

// Human-readable form for logs, e.g. "[1.4.0, 1.5.0)", "[1.4.0, +inf)" or
// "unconstrained".
[[nodiscard]] std::string to_string(const VersionRange& range);

}  // namespace tier::core
