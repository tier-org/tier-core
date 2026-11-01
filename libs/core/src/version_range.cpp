#include "tier/core/version_range.hpp"

#include <iterator>

#include "tier/core/networks_table.hpp"  // generated from the networks/ dir
#include "tier/core/seeds.hpp"           // is_valid_network_name

namespace tier::core {
namespace {

// Trim leading/trailing ASCII whitespace.
std::string_view trim(std::string_view s) noexcept {
  const auto is_ws = [](char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
  };
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && is_ws(s[b])) {
    ++b;
  }
  while (e > b && is_ws(s[e - 1])) {
    --e;
  }
  return s.substr(b, e - b);
}

std::string semver_to_string(const SemVer& v) {
  std::string out = std::to_string(v.major) + "." + std::to_string(v.minor) +
                    "." + std::to_string(v.patch);
  if (!v.prerelease.empty()) {
    out += "-" + v.prerelease;
  }
  return out;
}

}  // namespace

bool VersionRange::contains(const SemVer& v) const noexcept {
  if (min && compare_semver(v, *min) < 0) {
    return false;
  }
  if (max && compare_semver(v, *max) >= 0) {
    return false;
  }
  return true;
}

std::optional<VersionRange> parse_version_range(std::string_view spec) {
  const std::string_view s = trim(spec);
  if (s.empty()) {
    return VersionRange{};  // unconstrained
  }
  const std::size_t comma = s.find(',');
  if (comma == std::string_view::npos) {
    return std::nullopt;  // a range needs both sides, even if one is empty
  }
  if (s.find(',', comma + 1) != std::string_view::npos) {
    return std::nullopt;  // more than one comma
  }

  const std::string_view lo = trim(s.substr(0, comma));
  const std::string_view hi = trim(s.substr(comma + 1));

  VersionRange range;
  if (!lo.empty()) {
    const auto v = parse_semver(lo);
    if (!v) {
      return std::nullopt;
    }
    range.min = *v;
  }
  if (!hi.empty()) {
    const auto v = parse_semver(hi);
    if (!v) {
      return std::nullopt;
    }
    range.max = *v;
  }
  if (range.min && range.max && compare_semver(*range.max, *range.min) <= 0) {
    return std::nullopt;  // empty window: admits nothing, surely a config error
  }
  return range;
}

bool version_admitted(const VersionRange& range, std::string_view version) {
  if (range.unconstrained()) {
    return true;
  }
  const auto v = parse_semver(version);
  if (!v) {
    return true;  // empty or unparseable: cannot judge, admit leniently
  }
  return range.contains(*v);
}

VersionRange network_version_range(std::string_view network) {
  for (const auto& p : generated::kNetworkPolicies) {
    if (p.name == network) {
      // The baked spec is validated by a build-time test, so it parses; fall
      // back to unconstrained defensively if that ever fails to hold.
      if (const auto r = parse_version_range(p.version_range)) {
        return *r;
      }
      return {};
    }
  }
  return {};  // no baked file for this network (private): unconstrained
}

std::vector<NetworkPolicyInfo> baked_networks() {
  std::vector<NetworkPolicyInfo> out;
  out.reserve(std::size(generated::kNetworkPolicies));
  for (const auto& p : generated::kNetworkPolicies) {
    VersionRange r;
    if (const auto parsed = parse_version_range(p.version_range)) {
      r = *parsed;
    }
    out.push_back(NetworkPolicyInfo{std::string(p.name), r});
  }
  return out;
}

bool validate_baked_networks(std::string* error) {
  for (const auto& p : generated::kNetworkPolicies) {
    if (!is_valid_network_name(p.name)) {
      if (error != nullptr) {
        *error = "invalid network name '" + std::string(p.name) + "'";
      }
      return false;
    }
    if (!parse_version_range(p.version_range)) {
      if (error != nullptr) {
        *error = "network '" + std::string(p.name) + "': version_range '" +
                 std::string(p.version_range) + "' does not parse";
      }
      return false;
    }
  }
  return true;
}

std::string to_string(const VersionRange& range) {
  if (range.unconstrained()) {
    return "unconstrained";
  }
  std::string out = "[";
  out += range.min ? semver_to_string(*range.min) : "-inf";
  out += ", ";
  out += range.max ? semver_to_string(*range.max) : "+inf";
  out += ")";
  return out;
}

}  // namespace tier::core
