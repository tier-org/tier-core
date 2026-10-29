# Header-only seam for now. Implementations over aws-lc (the libcrypto backend)
# are added in a later step; the interfaces exist from day one so the rest of
# the stack never depends on a concrete algorithm (Ed25519 today, ML-DSA later).
add_library(tier_crypto INTERFACE)
add_library(tier::crypto ALIAS tier_crypto)

target_include_directories(tier_crypto INTERFACE include)
target_link_libraries(tier_crypto INTERFACE tier::options)
