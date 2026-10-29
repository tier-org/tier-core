add_library(tier_net STATIC src/endpoint.cpp)
add_library(tier::net ALIAS tier_net)

target_include_directories(tier_net PUBLIC include)
target_link_libraries(tier_net PUBLIC tier::options PRIVATE tier::crypto)
