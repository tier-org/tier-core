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
