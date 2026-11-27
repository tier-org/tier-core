#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace tier::agent {

enum class FileResult : std::uint8_t { ok, absent, exists, error };
using Seed = std::array<std::uint8_t, 32>;

// Install a new, private file atomically. Returns exists on a concurrent
// install. Existing files are left intact.
FileResult create_private_file(const std::string& path, std::string_view data);
// Best-effort mkdir -p for the parent of `path`, so a by-hand run works even
// without systemd's StateDirectory/RuntimeDirectory having created it.
void create_parent_dirs(const std::string& path);
FileResult read_seed_file(const std::string& path, Seed& seed);
bool load_or_create_seed(const std::string& path, Seed& seed);

}  // namespace tier::agent
