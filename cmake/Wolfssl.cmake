# wolfSSL is vendored as a pinned git submodule under vendor/wolfssl and built
# from source via its own CMake. We configure it through cache variables set
# before add_subdirectory; wolfSSL's add_option() creates each cache entry
# without FORCE, so a value pre-set here wins.
#
# v0 / base-layer identity scope: just what node identity needs — Ed25519
# (keypair + self-signed X.509), Curve25519 (for later ECDH), SHA-256, plus key
# and certificate generation. TLS 1.3 / QUIC / the OpenSSL-compat surface are
# enabled when the QUIC endpoint lands, to keep the attack surface minimal now.

set(WOLFSSL_EXAMPLES    "no"  CACHE BOOL "" FORCE)
set(WOLFSSL_CRYPT_TESTS "no"  CACHE BOOL "" FORCE)
set(WOLFSSL_HARDEN      "yes" CACHE BOOL "" FORCE)  # timing / side-channel resistance
set(WOLFSSL_ED25519     "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_CURVE25519  "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_SHA256      "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_KEYGEN      "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_CERTGEN     "yes" CACHE BOOL "" FORCE)

add_subdirectory(vendor/wolfssl EXCLUDE_FROM_ALL)
add_library(tier::wolfssl ALIAS wolfssl)

# Expose wolfSSL's headers to our code as SYSTEM includes, so Tier's strict
# -Werror warning set does not fire on wolfSSL's C macros and headers.
get_target_property(_tier_wolfssl_includes wolfssl INTERFACE_INCLUDE_DIRECTORIES)
if(_tier_wolfssl_includes)
  set_target_properties(wolfssl PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_tier_wolfssl_includes}")
endif()
