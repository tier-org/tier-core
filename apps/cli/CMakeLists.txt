add_executable(tierctl src/main.cpp)
target_link_libraries(tierctl PRIVATE tier::core tier::options)

include(GNUInstallDirs)
install(TARGETS tierctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
