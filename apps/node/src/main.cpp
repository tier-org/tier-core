#include <iostream>

#include "tier/core/version.hpp"

int main() {
  std::cout << "tier-node " << tier::core::version() << '\n';
  std::cout << "skeleton: networking not implemented yet\n";
  return 0;
}
