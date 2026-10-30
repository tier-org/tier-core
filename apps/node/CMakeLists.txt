add_executable(tier-node src/main.cpp)
target_link_libraries(tier-node PRIVATE tier::net tier::crypto tier::options)

include(GNUInstallDirs)
install(TARGETS tier-node RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
