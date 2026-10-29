add_executable(test_version test_version.cpp)
target_link_libraries(test_version PRIVATE tier::core tier::options)
add_test(NAME version COMMAND test_version)
