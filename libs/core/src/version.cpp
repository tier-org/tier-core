#include "tier/core/version.hpp"

#ifndef TIER_VERSION
#define TIER_VERSION "0.0.0"
#endif

namespace tier::core {

std::string_view version() noexcept { return TIER_VERSION; }

}  // namespace tier::core
