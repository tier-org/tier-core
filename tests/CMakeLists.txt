add_executable(test_version test_version.cpp)
target_link_libraries(test_version PRIVATE tier::core tier::options)
add_test(NAME version COMMAND test_version)

add_executable(test_identity test_identity.cpp)
target_link_libraries(test_identity PRIVATE tier::crypto tier::options)
add_test(NAME identity COMMAND test_identity)

add_executable(test_membership test_membership.cpp)
target_link_libraries(test_membership PRIVATE tier::core tier::options)
add_test(NAME membership COMMAND test_membership)

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
