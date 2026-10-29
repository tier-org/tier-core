#pragma once

#include <string_view>

namespace tier::core {

// Returns the project's semantic version string.
[[nodiscard]] std::string_view version() noexcept;

}  // namespace tier::core
