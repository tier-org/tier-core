# tier-messenger: interactive TUI client. The core (store + node client) is a
# library so it can be unit tested without the terminal UI; the executable adds
# the FTXUI front end. Built only when TIER_MESSENGER=ON (see the top-level
# CMakeLists); depends on the vendored SQLite and FTXUI.
add_library(tier_messenger_core STATIC
  src/store.cpp
  src/node_client.cpp)
add_library(tier::messenger_core ALIAS tier_messenger_core)
target_include_directories(tier_messenger_core PUBLIC src)
target_link_libraries(tier_messenger_core
  PUBLIC tier::core tier::app tier::sqlite tier::options)

add_executable(tier-messenger
  src/main.cpp
  src/ui.cpp)
target_link_libraries(tier-messenger
  PRIVATE tier::messenger_core tier::options
          ftxui::component ftxui::dom ftxui::screen)

include(GNUInstallDirs)
install(TARGETS tier-messenger RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
