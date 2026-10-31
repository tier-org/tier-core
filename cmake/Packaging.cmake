# Debian packaging via CPack. Produces a single .deb carrying the statically
# linked tierd binary, a hardened systemd unit, and a default environment
# file. Driven by `cpack -G DEB` from the build tree after a Release build.
#
# The vendored transport/crypto (ngtcp2, wolfSSL) and the C++ runtime are linked
# statically, so the only shared dependency is glibc; dpkg-shlibdeps derives the
# exact `libc6 (>= X)` floor from the built binary. That floor is set by the
# glibc of the build host, which is why release builds run on the oldest Ubuntu
# we intend to support.

include(GNUInstallDirs)

# systemd unit and the operator-editable environment file. The unit goes to
# ${libdir}/systemd/system (/usr/lib/systemd/system under the /usr prefix CPack
# uses); the env file is an absolute-path conffile under /etc.
install(FILES "${CMAKE_SOURCE_DIR}/packaging/systemd/tierd.service"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system")
install(FILES "${CMAKE_SOURCE_DIR}/packaging/tierd.env"
        DESTINATION "/etc/tier")

# Package version: PROJECT_VERSION by default, overridden from the git tag in CI
# via -DTIER_VERSION=<x.y.z>.
set(TIER_VERSION "${PROJECT_VERSION}" CACHE STRING "Debian package version")

set(CPACK_GENERATOR "DEB")
set(CPACK_STRIP_FILES TRUE)  # strip symbols from the packaged binary for size
set(CPACK_PACKAGE_NAME "tierd")
set(CPACK_PACKAGE_VERSION "${TIER_VERSION}")
set(CPACK_PACKAGE_CONTACT "Eugene Khashin <adastreamer@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Node daemon for Tier, a decentralized encrypted messaging/payments network")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
    "Node daemon for Tier, a decentralized network for encrypted messaging and payments. QUIC transport (ngtcp2 + OpenSSL) with Ed25519 certificate-bound identity, managed by systemd.")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Eugene Khashin <adastreamer@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
# Derive the libc6 (>= X) dependency from the built ELF rather than hardcoding.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
# tierd_<version>_<arch>.deb
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

set(_tier_debian "${CMAKE_SOURCE_DIR}/packaging/debian")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${_tier_debian}/conffiles;${_tier_debian}/postinst;${_tier_debian}/prerm;${_tier_debian}/postrm")

include(CPack)
