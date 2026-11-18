#ifndef TIER_NODE_ROLES_HPP
#define TIER_NODE_ROLES_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tier/core/membership.hpp"

// Role resolution for the node daemon: role-name <-> RoleSet helpers and the
// preset/roles precedence policy. Kept out of main.cpp and free of I/O so the
// precedence is unit-tested directly. The preset -> RoleSet table itself lives
// in tier::core (preset_roles), next to the Role enum; this header holds only
// the operator-facing policy (how env, file, preset and roles combine).
namespace tier::node {

inline const char* role_name(tier::core::Role role) {
  switch (role) {
    case tier::core::Role::client:
      return "client";
    case tier::core::Role::validator:
      return "validator";
    case tier::core::Role::keeper:
      return "keeper";
    case tier::core::Role::transmitter:
      return "transmitter";
    case tier::core::Role::communicator:
      return "communicator";
  }
  return "?";
}

// Render a role set as "client|validator|..." (just "-" if empty).
inline std::string format_roles(tier::core::RoleSet roles) {
  std::string out;
  for (const tier::core::Role r :
       {tier::core::Role::client, tier::core::Role::validator,
        tier::core::Role::keeper, tier::core::Role::transmitter,
        tier::core::Role::communicator}) {
    if (tier::core::has_role(roles, r)) {
      if (!out.empty()) {
        out += '|';
      }
      out += role_name(r);
    }
  }
  return out.empty() ? "-" : out;
}

// Parse an explicit role list: role names separated by '|', ',' or whitespace,
// e.g. "transmitter" or "validator|keeper". A nullptr or empty spec yields the
// plain client role, so the default node is an edge node (dial-out only) - see
// docs/topology.md. Returns std::nullopt on an unknown name so the caller can
// fail closed with a diagnostic.
inline std::optional<tier::core::RoleSet> parse_roles(const char* spec) {
  if (spec == nullptr) {
    return tier::core::role_bit(tier::core::Role::client);
  }
  tier::core::RoleSet roles = 0;
  std::string token;
  const auto flush = [&]() -> bool {
    if (token.empty()) {
      return true;
    }
    bool matched = false;
    for (const tier::core::Role r :
         {tier::core::Role::client, tier::core::Role::validator,
          tier::core::Role::keeper, tier::core::Role::transmitter,
          tier::core::Role::communicator}) {
      if (token == role_name(r)) {
        roles |= tier::core::role_bit(r);
        matched = true;
        break;
      }
    }
    token.clear();
    return matched;
  };
  for (const char c : std::string_view(spec)) {
    if (c == '|' || c == ',' || c == ' ' || c == '\t') {
      if (!flush()) {
        return std::nullopt;
      }
    } else {
      token.push_back(c);
    }
  }
  if (!flush()) {
    return std::nullopt;
  }
  if (roles == 0) {
    roles = tier::core::role_bit(tier::core::Role::client);
  }
  return roles;
}

struct RoleResolution {
  tier::core::RoleSet roles = 0;
  std::string preset;  // the preset applied; empty if roles were explicit
  bool roles_ignored = false;  // a preset won over an explicit roles list
  std::string error;           // non-empty => fatal (unknown preset/role name)
  bool ok = false;
};

// Resolve the effective role set from a preset name or an explicit role list,
// across the environment and file layers.
//
// A layer that sets either a preset or roles wins over the lower layer (env over
// file). Within the winning layer a preset takes precedence over an explicit
// roles list - the roles are ignored (roles_ignored = true) rather than merged,
// so the code-controlled preset stays the single source of truth and can both
// add and remove roles on a future update. If no layer sets either, the default
// "client" preset applies. An unknown preset name or role name is fatal (error
// set, ok = false): a silent fallback would quietly demote a misconfigured
// infrastructure node to a plain client.
inline RoleResolution resolve_role_set(
    const char* env_preset, const char* env_roles,
    const std::optional<std::string>& file_preset,
    const std::optional<std::vector<std::string>>& file_roles) {
  const auto nonempty = [](const char* s) {
    return s != nullptr && *s != '\0';
  };
  RoleResolution out;

  std::optional<std::string> preset;
  std::optional<std::string> roles_spec;
  if (nonempty(env_preset) || nonempty(env_roles)) {
    if (nonempty(env_preset)) {
      preset = env_preset;
      out.roles_ignored = nonempty(env_roles);
    } else {
      roles_spec = std::string(env_roles);
    }
  } else if (file_preset.has_value() || file_roles.has_value()) {
    if (file_preset.has_value()) {
      preset = *file_preset;
      out.roles_ignored = file_roles.has_value();
    } else {
      std::string joined;
      for (const std::string& r : *file_roles) {
        if (!joined.empty()) {
          joined += '|';
        }
        joined += r;
      }
      roles_spec = std::move(joined);
    }
  } else {
    preset = "client";  // nothing set anywhere: the default preset
  }

  if (preset.has_value()) {
    const auto resolved = tier::core::preset_roles(*preset);
    if (!resolved) {
      out.error = "unknown preset '" + *preset + "' (expected one of " +
                  std::string(tier::core::preset_names()) + ")";
      return out;
    }
    out.roles = *resolved;
    out.preset = *preset;
    out.ok = true;
    return out;
  }

  const auto resolved = parse_roles(roles_spec->c_str());
  if (!resolved) {
    out.error = "invalid roles '" + *roles_spec +
                "' (expected names from "
                "client|validator|keeper|transmitter|communicator, e.g. "
                "\"transmitter\" or \"validator|keeper\")";
    return out;
  }
  out.roles = *resolved;
  out.ok = true;
  return out;
}

}  // namespace tier::node

#endif  // TIER_NODE_ROLES_HPP
