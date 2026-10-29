add_library(tier_core STATIC src/version.cpp)
add_library(tier::core ALIAS tier_core)

target_include_directories(tier_core PUBLIC include)
target_link_libraries(tier_core PUBLIC tier::options)
target_compile_definitions(tier_core PRIVATE TIER_VERSION="${PROJECT_VERSION}")
