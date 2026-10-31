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
