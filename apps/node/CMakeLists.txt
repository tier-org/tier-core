add_executable(tier-node src/main.cpp)
target_link_libraries(tier-node PRIVATE tier::core tier::options)
