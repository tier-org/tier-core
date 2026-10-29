cmake_minimum_required(VERSION 3.25)
project(tier-core LANGUAGES CXX VERSION 0.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(TIER_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" ON)
option(TIER_WERROR "Treat warnings as errors" ON)
option(TIER_FUZZ "Build libFuzzer targets (requires Clang)" OFF)

include(cmake/CompilerOptions.cmake)
include(cmake/Sanitizers.cmake)

enable_testing()

add_subdirectory(libs/core)
add_subdirectory(libs/crypto)
add_subdirectory(libs/net)
add_subdirectory(apps/node)
add_subdirectory(apps/cli)
add_subdirectory(tests)

if(TIER_FUZZ)
  add_subdirectory(fuzz)
endif()
