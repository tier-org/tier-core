add_executable(tierd src/main.cpp)
target_link_libraries(tierd PRIVATE tier::net tier::crypto tier::options)

include(GNUInstallDirs)
install(TARGETS tierd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
