# tier-vanity: a developer tool that grinds Ed25519 identities for a vanity
# bech32m address prefix. Built with the tree but intentionally NOT installed -
# it is an operator convenience, not part of the node/messenger runtime.
add_executable(tier-vanity src/main.cpp)
find_package(Threads REQUIRED)
target_link_libraries(tier-vanity
  PRIVATE tier::crypto tier::core tier::options Threads::Threads)
