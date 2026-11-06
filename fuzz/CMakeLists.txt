if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "tier: TIER_FUZZ requires Clang; skipping fuzz targets")
  return()
endif()

# Each decoder of untrusted input gets a libFuzzer target (see the security
# process in the spec). fuzz_frame drives the wire-frame length-prefix decoder
# (tier::net::framing::take_frame), which is header-only, so it needs the net and
# crypto include paths but not the heavy transport library.
add_executable(fuzz_frame fuzz_frame.cpp)
target_link_libraries(fuzz_frame PRIVATE tier::options)
target_include_directories(fuzz_frame PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/net/include"
  "${CMAKE_SOURCE_DIR}/libs/crypto/include")
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

# Parsers of the version string (gossiped PeerInfo::version) and the version
# range (TIER_VERSION_RANGE) - untrusted / operator input.
add_executable(fuzz_semver fuzz_semver.cpp)
target_link_libraries(fuzz_semver PRIVATE tier::core tier::options)
target_compile_options(fuzz_semver PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_semver PRIVATE -fsanitize=fuzzer)

# Decoders of the sealed application message and the enc_keys announce
# (untrusted peer input, with real signature/decrypt paths behind them).
add_executable(fuzz_sealed fuzz_sealed.cpp)
target_link_libraries(fuzz_sealed PRIVATE tier::msg tier::crypto tier::core tier::options)
target_compile_options(fuzz_sealed PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_sealed PRIVATE -fsanitize=fuzzer)

add_executable(fuzz_presence fuzz_presence.cpp)
target_link_libraries(fuzz_presence PRIVATE tier::msg tier::crypto tier::core tier::options)
target_compile_options(fuzz_presence PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_presence PRIVATE -fsanitize=fuzzer)

add_executable(fuzz_user fuzz_user.cpp)
target_link_libraries(fuzz_user PRIVATE tier::msg tier::crypto tier::core tier::options)
target_compile_options(fuzz_user PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_user PRIVATE -fsanitize=fuzzer)

add_executable(fuzz_holepunch fuzz_holepunch.cpp)
target_link_libraries(fuzz_holepunch PRIVATE tier::msg tier::crypto tier::core tier::options)
target_compile_options(fuzz_holepunch PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_holepunch PRIVATE -fsanitize=fuzzer)

# Decoders of the application frame (layer 2, remote-controlled inner plaintext)
# and the admin stream-event push records.
add_executable(fuzz_app fuzz_app.cpp)
target_link_libraries(fuzz_app PRIVATE tier::app tier::core tier::options)
target_compile_options(fuzz_app PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_app PRIVATE -fsanitize=fuzzer)
