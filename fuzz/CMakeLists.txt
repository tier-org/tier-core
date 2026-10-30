if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "tier: TIER_FUZZ requires Clang; skipping fuzz targets")
  return()
endif()

# Each decoder of untrusted input gets a libFuzzer target (see the security
# process in the spec). fuzz_frame is the placeholder for the wire-frame decoder.
add_executable(fuzz_frame fuzz_frame.cpp)
target_link_libraries(fuzz_frame PRIVATE tier::options)
target_compile_options(fuzz_frame PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_frame PRIVATE -fsanitize=fuzzer)

# Decoder of the membership control message (untrusted peer input).
add_executable(fuzz_membership fuzz_membership.cpp)
target_link_libraries(fuzz_membership PRIVATE tier::core tier::options)
target_compile_options(fuzz_membership PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_membership PRIVATE -fsanitize=fuzzer)

# Decoders of the SWIM probe messages (ping / ack / ping_req).
add_executable(fuzz_control fuzz_control.cpp)
target_link_libraries(fuzz_control PRIVATE tier::core tier::options)
target_compile_options(fuzz_control PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_control PRIVATE -fsanitize=fuzzer)
