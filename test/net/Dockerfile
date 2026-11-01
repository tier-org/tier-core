# Runtime image for the localnet / e2e harness. The node binary is static (only
# libc6), so a thin base matching the packaging glibc floor (Ubuntu 22.04) is
# enough. tierd and tierctl are staged into ./bin by build.sh before the build.
FROM ubuntu:22.04

# Labelled so build.sh can prune only this harness's dangling layers (the label
# survives on an image after a rebuild moves its tag away).
LABEL tier.harness=localnet

COPY bin/tierd bin/tierctl /usr/local/bin/

# Admin socket (for tierctl) and the node identity live inside the container;
# each node generates its own Ed25519 key on first start. TIER_SEEDS is set per
# service in docker-compose.yml and fully replaces the baked production seeds.
# TIER_NETWORK puts the mesh on a private cluster ("localnet"), isolated from
# mainnet at the handshake even if an address happened to overlap.
ENV TIER_ADMIN_SOCK=/run/tierd/tierd.sock \
    TIER_ID_FILE=/var/lib/tier/node_key \
    TIER_NETWORK=localnet

RUN mkdir -p /run/tierd /var/lib/tier

# Dual-stack listen on [::]:7777 (serves IPv4 too); overridable via compose.
ENTRYPOINT ["/usr/local/bin/tierd"]
CMD ["run", "7777"]
