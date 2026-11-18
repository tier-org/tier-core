#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "roles.hpp"
#include "tier/core/membership.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::core::Role;
using tier::core::role_bit;
using tier::core::RoleSet;

constexpr RoleSet kValidator = static_cast<RoleSet>(
    role_bit(Role::client) | role_bit(Role::validator) |
    role_bit(Role::transmitter) | role_bit(Role::communicator));

// Shorthand for the file layer: an explicit roles list.
std::optional<std::vector<std::string>> roles_list(
    std::vector<std::string> v) {
  return std::optional<std::vector<std::string>>{std::move(v)};
}

}  // namespace

int main() {
  // --- preset_roles table (tier::core) ---
  {
    const auto client = tier::core::preset_roles("client");
    check(client && *client == role_bit(Role::client), "preset client -> client");

    const auto validator = tier::core::preset_roles("validator");
    check(validator && *validator == kValidator,
          "preset validator -> client|validator|transmitter|communicator");
    // validator preset must NOT grant keeper.
    check(validator && !tier::core::has_role(*validator, Role::keeper),
          "preset validator excludes keeper");

    const auto ganesha = tier::core::preset_roles("ganesha");
    check(ganesha && *ganesha == tier::core::kAllRoles,
          "preset ganesha -> kAllRoles");

    check(!tier::core::preset_roles("validater").has_value(),
          "unknown preset -> nullopt");
    check(!tier::core::preset_roles("").has_value(),
          "empty preset name -> nullopt");
  }

  // --- resolve_role_set precedence (tier::node) ---
  using tier::node::resolve_role_set;

  // Nothing set anywhere: default "client" preset.
  {
    const auto r = resolve_role_set(nullptr, nullptr, std::nullopt, std::nullopt);
    check(r.ok && r.preset == "client" && r.roles == role_bit(Role::client),
          "default -> client preset");
    check(!r.roles_ignored, "default sets no roles_ignored");
  }

  // File preset only.
  {
    const auto r = resolve_role_set(nullptr, nullptr,
                                    std::optional<std::string>{"validator"},
                                    std::nullopt);
    check(r.ok && r.preset == "validator" && r.roles == kValidator,
          "file preset validator");
  }

  // File roles only (legacy explicit path): no preset, exact roles.
  {
    const auto r = resolve_role_set(nullptr, nullptr, std::nullopt,
                                    roles_list({"validator", "keeper"}));
    check(r.ok && r.preset.empty(), "file roles -> no preset");
    check(r.roles == static_cast<RoleSet>(role_bit(Role::validator) |
                                          role_bit(Role::keeper)),
          "file roles -> validator|keeper");
    check(!r.roles_ignored, "file roles alone: nothing ignored");
  }

  // Both in the file layer: preset wins, roles ignored (not merged).
  {
    const auto r = resolve_role_set(nullptr, nullptr,
                                    std::optional<std::string>{"validator"},
                                    roles_list({"keeper"}));
    check(r.ok && r.preset == "validator" && r.roles == kValidator,
          "file preset+roles: preset wins");
    check(r.roles_ignored, "file preset+roles: roles_ignored flagged");
    check(!tier::core::has_role(r.roles, Role::keeper),
          "file preset+roles: keeper NOT merged in");
  }

  // Env overrides file: env preset beats a file roles list.
  {
    const auto r = resolve_role_set("ganesha", nullptr, std::nullopt,
                                    roles_list({"validator"}));
    check(r.ok && r.preset == "ganesha" && r.roles == tier::core::kAllRoles,
          "env preset overrides file roles");
  }

  // Env roles beats a file preset (env layer wins, and within it roles are the
  // only thing set).
  {
    const auto r = resolve_role_set(nullptr, "transmitter",
                                    std::optional<std::string>{"validator"},
                                    std::nullopt);
    check(r.ok && r.preset.empty() && r.roles == role_bit(Role::transmitter),
          "env roles overrides file preset");
  }

  // Empty env strings are treated as unset, falling through to the file layer.
  {
    const auto r = resolve_role_set("", "",
                                    std::optional<std::string>{"validator"},
                                    std::nullopt);
    check(r.ok && r.preset == "validator", "empty env ignored, file preset used");
  }

  // Unknown preset name is fatal.
  {
    const auto r = resolve_role_set(nullptr, nullptr,
                                    std::optional<std::string>{"validater"},
                                    std::nullopt);
    check(!r.ok && !r.error.empty(), "unknown preset -> fatal error");
  }

  // Unknown role name is fatal.
  {
    const auto r = resolve_role_set(nullptr, "wizard", std::nullopt,
                                    std::nullopt);
    check(!r.ok && !r.error.empty(), "unknown role -> fatal error");
  }

  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  std::printf("all preset tests passed\n");
  return 0;
}
