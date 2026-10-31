# OpenSSL 3.5 is vendored as a pinned git submodule under vendor/openssl and
# built here from source. OpenSSL uses its own Perl `Configure`, not CMake, so
# it is driven through ExternalProject: an out-of-tree, static-only build that
# installs just the development files (headers + libcrypto.a/libssl.a) we link.
#
# OpenSSL 3.5 provides the QUIC TLS API that ngtcp2's "ossl" crypto backend uses
# (no quictls fork needed) and the post-quantum groups (X25519MLKEM768). We keep
# the build lean (no apps/docs/tests, static only); algorithm pruning for size
# lives in a later pass so a working handshake comes first.

include(ExternalProject)
include(ProcessorCount)

ProcessorCount(_ossl_jobs)
if(_ossl_jobs EQUAL 0)
  set(_ossl_jobs 2)
endif()

set(_ossl_src "${CMAKE_CURRENT_SOURCE_DIR}/vendor/openssl")
set(_ossl_install "${CMAKE_CURRENT_BINARY_DIR}/vendor/openssl/install")
set(_ossl_incdir "${_ossl_install}/include")
set(_ossl_libcrypto "${_ossl_install}/lib/libcrypto.a")
set(_ossl_libssl "${_ossl_install}/lib/libssl.a")

# INTERFACE_INCLUDE_DIRECTORIES must exist at generate time; it is populated by
# the build below.
file(MAKE_DIRECTORY "${_ossl_incdir}")

ExternalProject_Add(openssl_ext
  SOURCE_DIR "${_ossl_src}"
  CONFIGURE_COMMAND
    perl "${_ossl_src}/Configure"
      "--prefix=${_ossl_install}"
      "--libdir=lib"
      no-shared no-apps no-docs no-tests no-dso no-module
      no-ssl3 no-tls1 no-tls1_1 no-dtls
      no-comp no-engine no-legacy no-deprecated no-weak-ssl-ciphers
      # Drop legacy ciphers/digests unused by TLS 1.3 and our primitives (we
      # keep RSA/DH/EC for X.509 and the handshake, ChaCha20-Poly1305/AES/SHA2,
      # and ML-KEM). This trims libcrypto for size without touching our paths.
      no-md4 no-mdc2 no-rmd160 no-whirlpool
      no-bf no-cast no-idea no-rc2 no-rc4 no-rc5 no-seed
      no-camellia no-aria no-sm2 no-sm3 no-sm4
      -O2
  BUILD_COMMAND make -j${_ossl_jobs} build_libs
  INSTALL_COMMAND make install_dev
  BUILD_IN_SOURCE 0
  BUILD_BYPRODUCTS "${_ossl_libcrypto}" "${_ossl_libssl}"
  LOG_CONFIGURE 1
  LOG_BUILD 1
  LOG_INSTALL 1)

# Umbrella target: link order is libssl before libcrypto (ssl depends on crypto);
# OpenSSL needs threads and libdl.
find_package(Threads REQUIRED)
add_library(tier_openssl INTERFACE)
target_include_directories(tier_openssl SYSTEM INTERFACE "${_ossl_incdir}")
target_link_libraries(tier_openssl INTERFACE
  "${_ossl_libssl}" "${_ossl_libcrypto}" Threads::Threads ${CMAKE_DL_LIBS})
add_dependencies(tier_openssl openssl_ext)
add_library(tier::openssl ALIAS tier_openssl)
