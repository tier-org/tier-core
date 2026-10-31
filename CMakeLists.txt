cmake_minimum_required(VERSION 3.25)

# Single source of truth for the version: the top-level VERSION file. Git-
# agnostic (no `git describe`), readable by non-CMake tooling (`cat VERSION`),
# and embedded into the binary via tier::core (TIER_VERSION). The release tag
# should be v$(cat VERSION); CI may assert they match.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" TIER_VERSION_STR LIMIT_COUNT 1)
project(tier-core LANGUAGES C CXX VERSION ${TIER_VERSION_STR})

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

# Single statically-linked node binary; vendored deps build static too.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

# Directories created implicitly by install() must be world-readable (0755),
# independent of the build user's umask; otherwise the packaged /usr, /etc, ...
# inherit a restrictive mode that would be wrong in the .deb.
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

include(cmake/CompilerOptions.cmake)
include(cmake/Sanitizers.cmake)

# Vendored dependencies (configured, then built uninstrumented). Added after the
# Tier interface targets so sanitizer/warning flags on tier::options never reach
# third-party code.
include(cmake/Openssl.cmake)
include(cmake/Ngtcp2.cmake)

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

# Install rules + CPack DEB packaging (used by `cpack -G DEB` after a Release
# build; harmless for development builds).
include(cmake/Packaging.cmake)
