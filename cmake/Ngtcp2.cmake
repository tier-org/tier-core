# ngtcp2 is vendored as a pinned git submodule under vendor/ngtcp2. We build the
# core transport library (libngtcp2, which has no TLS dependency) via its own
# CMake in lib-only mode, so ngtcp2 never runs find_package() for a system TLS
# stack. The wolfSSL crypto backend (crypto/shared.c + crypto/wolfssl/wolfssl.c)
# we compile ourselves against our vendored wolfSSL target — the same code
# ngtcp2 would build, but wired to our pinned wolfSSL instead of a system one.

set(ENABLE_LIB_ONLY   ON  CACHE BOOL "" FORCE)  # core libngtcp2 only; no examples/crypto subdirs
set(ENABLE_STATIC_LIB ON  CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL    OFF CACHE BOOL "" FORCE)  # do not pull a system OpenSSL
set(ENABLE_WOLFSSL    OFF CACHE BOOL "" FORCE)  # we build the backend ourselves (below)
set(ENABLE_WERROR     OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING     OFF CACHE BOOL "" FORCE)

add_subdirectory(vendor/ngtcp2 EXCLUDE_FROM_ALL)

# Expose libngtcp2's headers to our code as SYSTEM includes (strict -Werror must
# not fire on ngtcp2's C headers).
get_target_property(_tier_ngtcp2_includes ngtcp2_static INTERFACE_INCLUDE_DIRECTORIES)
if(_tier_ngtcp2_includes)
  set_target_properties(ngtcp2_static PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_tier_ngtcp2_includes}")
endif()

# The wolfSSL crypto backend, built from ngtcp2's own sources against our
# vendored wolfSSL. NGTCP2_STATICLIB because we link the static core.
set(_ngtcp2_dir "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ngtcp2")
add_library(tier_ngtcp2_crypto_wolfssl STATIC
  "${_ngtcp2_dir}/crypto/shared.c"
  "${_ngtcp2_dir}/crypto/wolfssl/wolfssl.c")
target_compile_definitions(tier_ngtcp2_crypto_wolfssl
  PUBLIC NGTCP2_STATICLIB
  PRIVATE BUILDING_NGTCP2)

# Public: only the crypto backend's public header. Private: ngtcp2's internal
# lib/ and crypto/ headers plus the generated ones in the build tree — the same
# include set ngtcp2's own crypto/wolfssl/CMakeLists.txt uses to compile these
# sources. (wolfSSL's own include dirs arrive via the linked wolfssl target.)
set(_ngtcp2_bin "${CMAKE_CURRENT_BINARY_DIR}/vendor/ngtcp2")
target_include_directories(tier_ngtcp2_crypto_wolfssl SYSTEM PUBLIC
  "${_ngtcp2_dir}/crypto/includes")
target_include_directories(tier_ngtcp2_crypto_wolfssl PRIVATE
  "${_ngtcp2_dir}/lib/includes"
  "${_ngtcp2_bin}/lib/includes"
  "${_ngtcp2_dir}/lib"
  "${_ngtcp2_dir}/crypto/includes"
  "${_ngtcp2_bin}/crypto/includes"
  "${_ngtcp2_dir}/crypto"
  "${_ngtcp2_bin}/crypto"
  "${_ngtcp2_bin}")
target_link_libraries(tier_ngtcp2_crypto_wolfssl PUBLIC ngtcp2_static wolfssl)

# One handle for the stack: core transport + wolfSSL crypto backend + wolfSSL.
add_library(tier::ngtcp2 ALIAS tier_ngtcp2_crypto_wolfssl)
