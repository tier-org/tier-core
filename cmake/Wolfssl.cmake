# wolfSSL is vendored as a pinned git submodule under vendor/wolfssl and built
# from source via its own CMake. We configure it through cache variables set
# before add_subdirectory; wolfSSL's add_option() creates each cache entry
# without FORCE, so a value pre-set here wins.
#
# Scope: node identity (Ed25519 keypair + self-signed X.509, Curve25519 for
# later ECDH, SHA-256, key/cert generation) plus the TLS 1.3 QUIC handshake that
# the ngtcp2 wolfSSL crypto backend drives. WOLFSSL_QUIC is wolfSSL's dedicated
# switch for ngtcp2/curl; it pulls in ALPN, SNI and the OpenSSL-compat surface
# the backend calls into.

set(WOLFSSL_EXAMPLES      "no"  CACHE BOOL "" FORCE)
set(WOLFSSL_CRYPT_TESTS   "no"  CACHE BOOL "" FORCE)
set(WOLFSSL_HARDEN        "yes" CACHE BOOL "" FORCE)  # timing / side-channel resistance
set(WOLFSSL_ED25519       "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_CURVE25519    "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_SHA256        "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_KEYGEN        "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_CERTGEN       "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_TLS13         "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_QUIC          "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_SESSION_TICKET "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_EARLYDATA     "yes" CACHE BOOL "" FORCE)
set(WOLFSSL_AESECB        "yes" CACHE BOOL "" FORCE)  # QUIC header protection (AES-ECB)

add_subdirectory(vendor/wolfssl EXCLUDE_FROM_ALL)
add_library(tier::wolfssl ALIAS wolfssl)

# Expose wolfSSL's headers to our code as SYSTEM includes, so Tier's strict
# -Werror warning set does not fire on wolfSSL's C macros and headers.
get_target_property(_tier_wolfssl_includes wolfssl INTERFACE_INCLUDE_DIRECTORIES)
if(_tier_wolfssl_includes)
  set_target_properties(wolfssl PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_tier_wolfssl_includes}")
endif()
