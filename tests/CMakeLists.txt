add_executable(test_version test_version.cpp)
target_link_libraries(test_version PRIVATE tier::core tier::options)
add_test(NAME version COMMAND test_version)

add_executable(test_identity test_identity.cpp)
target_link_libraries(test_identity PRIVATE tier::crypto tier::options)
add_test(NAME identity COMMAND test_identity)

add_executable(test_crypto_primitives test_crypto_primitives.cpp)
target_link_libraries(test_crypto_primitives PRIVATE tier::crypto tier::options)
add_test(NAME crypto_primitives COMMAND test_crypto_primitives)

add_executable(test_sealed test_sealed.cpp)
target_link_libraries(test_sealed PRIVATE tier::msg tier::crypto tier::core tier::options)
add_test(NAME sealed COMMAND test_sealed)

add_executable(test_messaging test_messaging.cpp)
target_link_libraries(test_messaging PRIVATE tier::net tier::msg tier::core tier::crypto tier::options)
add_test(NAME messaging COMMAND test_messaging)

add_executable(test_discovery test_discovery.cpp)
target_link_libraries(test_discovery PRIVATE tier::net tier::msg tier::core tier::crypto tier::options)
add_test(NAME discovery COMMAND test_discovery)
set_tests_properties(discovery PROPERTIES TIMEOUT 60)

add_executable(test_multi_identity test_multi_identity.cpp)
target_link_libraries(test_multi_identity PRIVATE tier::net tier::msg tier::core tier::crypto tier::options)
add_test(NAME multi_identity COMMAND test_multi_identity)
set_tests_properties(multi_identity PROPERTIES TIMEOUT 90)

add_executable(test_user_directory test_user_directory.cpp)
target_link_libraries(test_user_directory PRIVATE tier::net tier::core tier::options)
add_test(NAME user_directory COMMAND test_user_directory)

add_executable(test_holepunch test_holepunch.cpp)
target_link_libraries(test_holepunch PRIVATE tier::net tier::msg tier::core tier::crypto tier::options)
add_test(NAME holepunch COMMAND test_holepunch)
set_tests_properties(holepunch PROPERTIES TIMEOUT 120)

add_executable(test_membership test_membership.cpp)
target_link_libraries(test_membership PRIVATE tier::core tier::options)
add_test(NAME membership COMMAND test_membership)

add_executable(test_presence test_presence.cpp)
target_link_libraries(test_presence PRIVATE tier::msg tier::crypto tier::core tier::options)
add_test(NAME presence COMMAND test_presence)

add_executable(test_user test_user.cpp)
target_link_libraries(test_user PRIVATE tier::msg tier::crypto tier::core tier::options)
add_test(NAME user COMMAND test_user)

add_executable(test_rendezvous test_rendezvous.cpp)
target_link_libraries(test_rendezvous PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME rendezvous COMMAND test_rendezvous)

add_executable(test_presence_registry test_presence_registry.cpp)
target_link_libraries(test_presence_registry PRIVATE tier::net tier::core tier::options)
add_test(NAME presence_registry COMMAND test_presence_registry)

add_executable(test_semver test_semver.cpp)
target_link_libraries(test_semver PRIVATE tier::core tier::options)
add_test(NAME semver COMMAND test_semver)

add_executable(test_version_range test_version_range.cpp)
target_link_libraries(test_version_range PRIVATE tier::core tier::options)
add_test(NAME version_range COMMAND test_version_range)

add_executable(test_control test_control.cpp)
target_link_libraries(test_control PRIVATE tier::core tier::options)
add_test(NAME control COMMAND test_control)

add_executable(test_send_queue test_send_queue.cpp)
target_link_libraries(test_send_queue PRIVATE tier::options)
target_include_directories(test_send_queue PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/net/include")
add_test(NAME send_queue COMMAND test_send_queue)

# The node config parser is a header in the daemon's source dir (apps/node/src),
# unit tested here without building the daemon.
add_executable(test_config test_config.cpp)
target_link_libraries(test_config PRIVATE tier::options)
target_include_directories(test_config PRIVATE
  "${CMAKE_SOURCE_DIR}/apps/node/src")
add_test(NAME config COMMAND test_config)

add_executable(test_net_backend test_net_backend.cpp)
target_link_libraries(test_net_backend PRIVATE tier::net tier::options)
add_test(NAME net_backend COMMAND test_net_backend)

add_executable(test_endpoint test_endpoint.cpp)
target_link_libraries(test_endpoint PRIVATE tier::net tier::crypto tier::options)
add_test(NAME endpoint COMMAND test_endpoint)
set_tests_properties(endpoint PROPERTIES TIMEOUT 30)

add_executable(test_node test_node.cpp)
target_link_libraries(test_node PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME node COMMAND test_node)
set_tests_properties(node PROPERTIES TIMEOUT 30)

add_executable(test_gossip test_gossip.cpp)
target_link_libraries(test_gossip PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME gossip COMMAND test_gossip)
set_tests_properties(gossip PROPERTIES TIMEOUT 60)

add_executable(test_bootstrap test_bootstrap.cpp)
target_link_libraries(test_bootstrap PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME bootstrap COMMAND test_bootstrap)
set_tests_properties(bootstrap PROPERTIES TIMEOUT 60)

add_executable(test_network test_network.cpp)
target_link_libraries(test_network PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME network COMMAND test_network)
set_tests_properties(network PROPERTIES TIMEOUT 60)

add_executable(test_ipv6 test_ipv6.cpp)
target_link_libraries(test_ipv6 PRIVATE tier::net tier::crypto tier::options)
add_test(NAME ipv6 COMMAND test_ipv6)
set_tests_properties(ipv6 PROPERTIES TIMEOUT 30)

add_executable(test_swim test_swim.cpp)
target_link_libraries(test_swim PRIVATE tier::core tier::options)
add_test(NAME swim COMMAND test_swim)
set_tests_properties(swim PROPERTIES TIMEOUT 30)

add_executable(test_swim_net test_swim_net.cpp)
target_link_libraries(test_swim_net PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME swim_net COMMAND test_swim_net)
set_tests_properties(swim_net PROPERTIES TIMEOUT 60)

add_executable(test_mesh test_mesh.cpp)
target_link_libraries(test_mesh PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME mesh COMMAND test_mesh)
set_tests_properties(mesh PROPERTIES TIMEOUT 60)

add_executable(test_topology test_topology.cpp)
target_link_libraries(test_topology PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME topology COMMAND test_topology)
set_tests_properties(topology PROPERTIES TIMEOUT 60)

add_executable(test_multiaddr test_multiaddr.cpp)
target_link_libraries(test_multiaddr PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME multiaddr COMMAND test_multiaddr)
set_tests_properties(multiaddr PROPERTIES TIMEOUT 30)

add_executable(test_dualstack test_dualstack.cpp)
target_link_libraries(test_dualstack PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME dualstack COMMAND test_dualstack)
set_tests_properties(dualstack PROPERTIES TIMEOUT 60)

add_executable(test_seeds test_seeds.cpp)
target_link_libraries(test_seeds PRIVATE tier::net tier::core tier::crypto tier::options)
add_test(NAME seeds COMMAND test_seeds)
set_tests_properties(seeds PROPERTIES TIMEOUT 60)

add_executable(test_symmetric test_symmetric.cpp)
target_link_libraries(test_symmetric PRIVATE tier::net tier::crypto tier::options)
add_test(NAME symmetric COMMAND test_symmetric)
set_tests_properties(symmetric PROPERTIES TIMEOUT 30)

add_executable(test_admin test_admin.cpp)
target_link_libraries(test_admin PRIVATE tier::core tier::options)
add_test(NAME admin COMMAND test_admin)

add_executable(test_admin_listener test_admin_listener.cpp)
target_link_libraries(test_admin_listener PRIVATE tier::net tier::core tier::options)
add_test(NAME admin_listener COMMAND test_admin_listener)
set_tests_properties(admin_listener PROPERTIES TIMEOUT 30)
