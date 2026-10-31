add_library(tier_net STATIC
  src/endpoint.cpp
  src/backend.cpp
  src/node.cpp
  src/admin_listener.cpp)
add_library(tier::net ALIAS tier_net)

target_include_directories(tier_net PUBLIC include)
target_link_libraries(tier_net
  PUBLIC tier::options tier::core tier::crypto
  PRIVATE tier::ngtcp2)
# endpoint.cpp includes OpenSSL headers (built by the ExternalProject), so they
# must exist before tier_net compiles.
add_dependencies(tier_net openssl_ext)
