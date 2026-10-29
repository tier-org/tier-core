# ASan + UBSan are applied globally so instrumentation stays consistent across
# all translation units and the sanitizer runtime links cleanly into binaries.
if(TIER_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  message(STATUS "tier: AddressSanitizer + UndefinedBehaviorSanitizer enabled")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()
