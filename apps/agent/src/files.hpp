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
FileResult read_seed_file(const std::string& path, Seed& seed);
bool load_or_create_seed(const std::string& path, Seed& seed);

}  // namespace tier::agent
