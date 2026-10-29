add_executable(tier-cli src/main.cpp)
target_link_libraries(tier-cli PRIVATE tier::core tier::options)
