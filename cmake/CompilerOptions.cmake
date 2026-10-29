# Shared compiler options carried as an interface target. Every target links
# tier::options so the strict, security-oriented warning set applies uniformly.
add_library(tier_options INTERFACE)
add_library(tier::options ALIAS tier_options)

target_compile_features(tier_options INTERFACE cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(tier_options INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2)
  if(TIER_WERROR)
    target_compile_options(tier_options INTERFACE -Werror)
  endif()
endif()
