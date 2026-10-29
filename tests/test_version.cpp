#include <string_view>

#include "tier/core/version.hpp"

// Minimal dependency-free test harness: return non-zero on failure, CTest reads
// the exit code. A real framework is deferred to keep the dependency set small.
int main() {
  const std::string_view v = tier::core::version();
  if (v.empty()) {
    return 1;
  }
  return 0;
}
