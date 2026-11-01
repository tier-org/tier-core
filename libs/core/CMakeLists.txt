# Bake the per-network policy files (top-level networks/) into a generated
# header. The files are the single source of truth; the binary never reads them
# at runtime. CONFIGURE_DEPENDS re-globs when a network file is added or removed.
set(TIER_NETWORKS_DIR "${CMAKE_SOURCE_DIR}/networks")
file(GLOB TIER_NETWORK_FILES CONFIGURE_DEPENDS "${TIER_NETWORKS_DIR}/*")
set(TIER_NETWORK_ENTRIES "")
foreach(_net_file ${TIER_NETWORK_FILES})
  get_filename_component(_net_name "${_net_file}" NAME)
  # Only policy files are network names; skip the directory's own README.
  if(_net_name MATCHES "\\.")
    continue()
  endif()
  if(NOT _net_name MATCHES "^[a-z0-9-]+$")
    message(FATAL_ERROR "networks/: invalid network name '${_net_name}' (expected [a-z0-9-])")
  endif()
  set(_net_range "")
  file(STRINGS "${_net_file}" _net_lines)
  foreach(_line ${_net_lines})
    if(_line MATCHES "^[ \t]*version_range[ \t]*=[ \t]*(.*)$")
      set(_net_range "${CMAKE_MATCH_1}")
      string(STRIP "${_net_range}" _net_range)
    endif()
  endforeach()
  if(_net_range MATCHES "[\"\\\\]")
    message(FATAL_ERROR "networks/${_net_name}: version_range contains an illegal character")
  endif()
  string(APPEND TIER_NETWORK_ENTRIES "    {\"${_net_name}\", \"${_net_range}\"},\n")
endforeach()
set(TIER_NETWORKS_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(networks_table.hpp.in
  "${TIER_NETWORKS_GENERATED_DIR}/tier/core/networks_table.hpp" @ONLY)

add_library(tier_core STATIC
  src/version.cpp
  src/semver.cpp
  src/version_range.cpp
  src/membership.cpp
  src/control.cpp
  src/admin.cpp
  src/swim.cpp)
add_library(tier::core ALIAS tier_core)

target_include_directories(tier_core PUBLIC include)
# The generated networks table is an implementation detail of version_range.cpp.
target_include_directories(tier_core PRIVATE "${TIER_NETWORKS_GENERATED_DIR}")
target_link_libraries(tier_core PUBLIC tier::options)
target_compile_definitions(tier_core PRIVATE TIER_VERSION="${PROJECT_VERSION}")
