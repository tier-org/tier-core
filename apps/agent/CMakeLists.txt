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
  src/admin_client.cpp)
target_link_libraries(tier-agent
  PRIVATE tier::agent_core tier::core tier::app tier::msg tier::crypto
          tier::options Threads::Threads)

# Packaging. The agent ships in the same .deb as tierd/tierctl/tier-messenger:
# the binary goes to bindir and the host-metrics exec source to libexecdir, so
# both are on standard paths. The role configs and the templated systemd unit go
# to the package doc dir as reference material (NOT /etc conffiles, NOT an active
# unit): an operator copies the config they need to /etc/tier/<instance>.toml and
# the unit to /etc/systemd/system, then `systemctl enable --now tier-agent@...`.
# Nothing here is auto-enabled - the agent is strictly opt-in per host.
include(GNUInstallDirs)
install(TARGETS tier-agent RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS integrations/host-metrics.sh
        DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/tier)
install(FILES integrations/agent.toml
              integrations/collector.toml
              integrations/tier-agent@.service
        DESTINATION share/doc/tierd/agent)
