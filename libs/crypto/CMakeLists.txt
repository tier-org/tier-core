# Cryptographic seam with a wolfSSL-backed implementation. The public headers
# stay backend-free (only std types and tier::crypto::Byte); wolfSSL is a
# private link dependency, so the rest of the stack never sees its headers and
# an algorithm swap (Ed25519 -> ML-DSA) stays local to this library.
add_library(tier_crypto STATIC
  src/ed25519.cpp
  src/identity.cpp)
add_library(tier::crypto ALIAS tier_crypto)

target_include_directories(tier_crypto PUBLIC include)
target_link_libraries(tier_crypto
  PUBLIC tier::options
  PRIVATE tier::wolfssl)
