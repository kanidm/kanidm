# Build the main Kanidmd server
ARG BASE_IMAGE=opensuse/tumbleweed:latest
# ARG BASE_IMAGE=opensuse/leap:15.5

FROM ${BASE_IMAGE} AS repos
ADD scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp /zypper_fixing.sh

# ======================
FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE="container_generic"
ARG KANIDM_BUILD_OPTIONS=""

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.mold"

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
        sccache \
        cargo \
        clang \
        gawk \
        make \
        automake \
        autoconf \
        libopenssl-3-devel \
        pam-devel \
        sqlite3-devel \
        systemd-devel \
        rsync \
        findutils \
        which \
        mold

COPY . /usr/src/kanidm

# ======================

WORKDIR /usr/src/kanidm/kanidmd/daemon

# Exports don't persist through RUN statements.
RUN --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo && \
    export SCCACHE_DIR=/sccache && \
    export RUSTC_WRAPPER=/usr/bin/sccache && \
    export CC="/usr/bin/clang" && \
    cargo build --locked -p daemon ${KANIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kanidm/target/" \
        --features="${KANIDM_FEATURES}" \
        --release; \
    sccache -s

# Find and copy dynamically linked libraries using ldd
# caveat: this actually partially runs the binary, so it doesn't work for cross-compilation
RUN <<EOF
    mkdir -p /out/libs
    mkdir -p /out/libs-root
    ldd /usr/src/kanidm/target/release/kanidmd
    ldd /usr/src/kanidm/target/release/kanidmd | grep -v 'linux-vdso.so' | awk '{print $(NF-1) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {}
    ls -Rla /out/libs
    ls -Rla /out/libs-root
EOF

# ======================

FROM scratch

WORKDIR /

# Copy root certs for tls into image
# You can also mount the certs from the host
# --volume /etc/ssl/certs:/etc/ssl/certs:ro
COPY --from=repos /etc/ssl/certs /etc/ssl/certs

# Copy our build
COPY --from=builder --chmod=0755 /usr/src/kanidm/target/release/kanidmd /sbin/
# Web assets
COPY --from=builder /usr/src/kanidm/server/core/static /hpkg/

# Copy fixed-path dynamic libraries to their position
COPY --from=builder /out/libs-root/ /
COPY --from=builder /out/libs/ /lib/

# Inform loader where to find libraries
# This is necessary because opensuse searches for libraries in /lib64 or /lib depending on the architecture, but we don't know which one we're on.
# Alternatively, we could symlink /lib64 to /lib, and /usr/lib64 to /usr/lib, etc.
# We could always fix this by invoking the loader on the host (which works in a cross build it seems), but this is easier.
# On debian, it always searches for libraries in /lib.
ENV LD_LIBRARY_PATH=/lib

WORKDIR /data

EXPOSE 8443 3636

ENV RUST_BACKTRACE=1

HEALTHCHECK \
    --interval=60s \
    --timeout=10s \
    --start-period=60s \
    --start-interval=5s \
    --retries=3 \
    CMD [ "/sbin/kanidmd", "healthcheck", "-c", "/data/server.toml"]

CMD [ "/sbin/kanidmd", "server"]
