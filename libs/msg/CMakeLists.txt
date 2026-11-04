# End-to-end encrypted application messages. Depends on the crypto seam for the
# primitives and on core for the control-plane type tags and PeerId. OpenSSL is
# reached only transitively through tier::crypto, so this library stays free of
# backend headers.
add_library(tier_msg STATIC
  src/sealed.cpp)
add_library(tier::msg ALIAS tier_msg)

target_include_directories(tier_msg PUBLIC include)
target_link_libraries(tier_msg
  PUBLIC tier::core tier::crypto tier::options)
