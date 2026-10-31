# ngtcp2 is vendored as a pinned git submodule under vendor/ngtcp2. We build the
# core transport library (libngtcp2, which has no TLS dependency) via its own
# CMake in lib-only mode, so ngtcp2 never runs find_package() for a system TLS
# stack. The OpenSSL ("ossl") crypto backend (crypto/shared.c + crypto/ossl/ossl.c)
# we compile ourselves against our vendored OpenSSL target -the same code ngtcp2
# would build, but wired to our pinned OpenSSL 3.5 instead of a system one.

set(ENABLE_LIB_ONLY   ON  CACHE BOOL "" FORCE)  # core libngtcp2 only; no examples/crypto subdirs
set(ENABLE_STATIC_LIB ON  CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL    OFF CACHE BOOL "" FORCE)  # no find_package; we build the ossl backend ourselves (below)
set(ENABLE_WOLFSSL    OFF CACHE BOOL "" FORCE)
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

# The OpenSSL ("ossl") crypto backend, built from ngtcp2's own sources against
# our vendored OpenSSL 3.5. This backend uses OpenSSL 3.5's mainline QUIC TLS
# API (no quictls fork). NGTCP2_STATICLIB because we link the static core.
set(_ngtcp2_dir "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ngtcp2")
add_library(tier_ngtcp2_crypto_ossl STATIC
  "${_ngtcp2_dir}/crypto/shared.c"
  "${_ngtcp2_dir}/crypto/ossl/ossl.c")
target_compile_definitions(tier_ngtcp2_crypto_ossl
  PUBLIC NGTCP2_STATICLIB
  PRIVATE BUILDING_NGTCP2)
# ossl.c includes OpenSSL headers, so OpenSSL must be built first.
add_dependencies(tier_ngtcp2_crypto_ossl openssl_ext)

# Public: only the crypto backend's public header. Private: ngtcp2's internal
# lib/ and crypto/ headers plus the generated ones in the build tree -the same
# include set ngtcp2's own crypto/ossl/CMakeLists.txt uses to compile these
# sources. (OpenSSL's own include dirs arrive via the linked tier::openssl.)
set(_ngtcp2_bin "${CMAKE_CURRENT_BINARY_DIR}/vendor/ngtcp2")
target_include_directories(tier_ngtcp2_crypto_ossl SYSTEM PUBLIC
  "${_ngtcp2_dir}/crypto/includes")
target_include_directories(tier_ngtcp2_crypto_ossl PRIVATE
  "${_ngtcp2_dir}/lib/includes"
  "${_ngtcp2_bin}/lib/includes"
  "${_ngtcp2_dir}/lib"
  "${_ngtcp2_dir}/crypto/includes"
  "${_ngtcp2_bin}/crypto/includes"
  "${_ngtcp2_dir}/crypto"
  "${_ngtcp2_bin}/crypto"
  "${_ngtcp2_bin}")
target_link_libraries(tier_ngtcp2_crypto_ossl PUBLIC ngtcp2_static tier::openssl)

# One handle for the stack: core transport + OpenSSL crypto backend + OpenSSL.
add_library(tier::ngtcp2 ALIAS tier_ngtcp2_crypto_ossl)
