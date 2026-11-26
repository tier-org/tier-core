# tier-agent: application-layer monitoring daemon over tierd's admin socket. One
# per-node actor whose role is set by config (agent ships metrics, collector
# receives/stores, both does both) - the serf/consul "agent" model. A separate
# product on top of the network; it changes nothing in the core. Built with the
# tree; not installed by default yet (MVP). The reusable core (envelope codec,
# config, store) is a static library so tests and a future keeper can link it
# without the binary. Shipped with the node package (see the install() rules at
# the end of this file), like tierctl and tier-messenger.
add_library(tier_agent_core STATIC
  src/envelope.cpp
  src/config.cpp
  src/store.cpp
  src/batcher.cpp)
target_include_directories(tier_agent_core PUBLIC src)
target_link_libraries(tier_agent_core PUBLIC tier::core PRIVATE tier::options)
add_library(tier::agent_core ALIAS tier_agent_core)

find_package(Threads REQUIRED)
add_executable(tier-agent
  src/main.cpp
  src/admin_client.cpp
  src/bootstrap.cpp
  src/files.cpp)
target_link_libraries(tier-agent
  PRIVATE tier::agent_core tier::core tier::app tier::msg tier::crypto
          tier::options Threads::Threads)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  view/index.html view/view.js)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/view/index.html" TIER_VIEW_HTML)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/view/view.js" TIER_VIEW_JS)
configure_file(view/assets.hpp.in view_assets.hpp @ONLY)
add_executable(tier-agent-view src/view_main.cpp)
target_include_directories(tier-agent-view PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(tier-agent-view PRIVATE tier::options)

# The role templates are used by bootstrap and support manual configuration.
# Package installation makes the units available for explicit activation.
include(GNUInstallDirs)
install(TARGETS tier-agent tier-agent-view RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS integrations/host-metrics.sh
        DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/tier)
install(FILES integrations/tier-agent@.service
              integrations/tier-agent-view.service
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system")
install(FILES integrations/agent.toml
              integrations/collector.toml
        DESTINATION "${CMAKE_INSTALL_DATADIR}/tier/agent")
install(FILES integrations/agent.toml
              integrations/collector.toml
              integrations/tier-agent@.service
              integrations/tier-agent-view.service
              collector-view.md
        DESTINATION share/doc/tierd/agent)
