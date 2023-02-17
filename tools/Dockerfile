# This builds the kanidm CLI tools
ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper mr -k repo-oss && \
    zypper mr -k repo-non-oss && \
    zypper mr -k repo-update && \
    zypper dup -y

# ======================
FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE
ARG KANIDM_BUILD_OPTIONS=""

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.mold"

# fixing the issue with getting OOMKilled in BuildKit
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
        sccache \
        cargo \
        clang \
        make automake autoconf \
        libopenssl-3-devel \
        pam-devel \
        libudev-devel \
        sqlite3-devel \
        rsync \
        mold

COPY . /usr/src/kanidm

WORKDIR /usr/src/kanidm/

# build the CLI
RUN \
--mount=type=cache,id=cargo,target=/cargo \
--mount=type=cache,id=sccache,target=/sccache \
export CARGO_HOME=/cargo; \
export SCCACHE_DIR=/sccache; \
export RUSTC_WRAPPER=/usr/bin/sccache; \
export CC="/usr/bin/clang"; \
    cargo build -p kanidm_tools ${KANIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kanidm/target/" \
        --features="${KANIDM_FEATURES}" \
        --release; \
    cargo build -p kanidm-ipa-sync ${KANIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kanidm/target/" \
        --features="${KANIDM_FEATURES}" \
        --release; \
    sccache -s

# == Construct the tools container
FROM repos

ENV RUST_BACKTRACE 1

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y timezone busybox-adduser openssl-3

COPY --from=builder /usr/src/kanidm/target/release/kanidm /sbin/
COPY --from=builder /usr/src/kanidm/target/release/kanidm-ipa-sync /sbin/
RUN chmod +x /sbin/kanidm
RUN chmod +x /sbin/kanidm-ipa-sync

RUN adduser -D -H kanidm && \
    mkdir /etc/kanidm && \
    touch /etc/kanidm/config

USER kanidm

CMD [ "/sbin/kanidm", "-h" ]

