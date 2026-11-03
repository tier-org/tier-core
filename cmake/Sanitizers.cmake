# ASan + UBSan apply to Tier's own code only, carried on the tier::options
# interface target rather than globally. Vendored dependencies (OpenSSL) must
# stay uninstrumented: UBSan with -fno-sanitize-recover would abort on
# constructs that are legal in audited C crypto code (intentional unsigned
# wraparound, type punning), and the fuzzing discipline targets our own
# decoders of untrusted input, not third-party libraries.
if(TIER_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  message(STATUS "tier: AddressSanitizer + UndefinedBehaviorSanitizer enabled (Tier targets only)")
  target_compile_options(tier_options INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_options(tier_options INTERFACE -fsanitize=address,undefined)
endif()

# libFuzzer coverage instrumentation, carried on tier::options so the decoders
# that actually parse untrusted input (control.cpp, semver.cpp, admin.cpp, the
# header-only framing) are instrumented, not just each fuzz target's entry
# function - without this libFuzzer is blind to the library code it is meant to
# explore and degrades to random input. "-no-link" keeps the libFuzzer main out
# of the libraries; only the fuzz executables pull it in (-fsanitize=fuzzer in
# fuzz/CMakeLists.txt). Vendored deps stay uninstrumented (added later, and they
# do not link tier::options). Pair with TIER_SANITIZE=ON so a fuzz-found memory
# or UB error actually aborts.
if(TIER_FUZZ AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(STATUS "tier: libFuzzer coverage instrumentation enabled (Tier targets only)")
  target_compile_options(tier_options INTERFACE -fsanitize=fuzzer-no-link)
endif()
