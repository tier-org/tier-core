#include <iostream>

#include "tier/core/version.hpp"

int main() {
  std::cout << "tier-cli " << tier::core::version() << '\n';
  return 0;
}
