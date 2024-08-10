# This builds the kanidm CLI tools
ARG BASE_IMAGE=opensuse/tumbleweed:latest
# ARG BASE_IMAGE=opensuse/leap:15.5

FROM ${BASE_IMAGE} AS repos
ADD ../../scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp /zypper_fixing.sh

FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE
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
        make \
        automake \
        autoconf \
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
    cargo build -p orca ${KANIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kanidm/target/" \
        --features="${KANIDM_FEATURES}" \
        --release && \
    cargo install \
        --git https://github.com/kanidm/webauthn-rs.git \
        --rev 5f4db4172f8e22aedc68c282d177e98db2b1892f \
        --force fido-mds-tool \
        --target-dir="/usr/src/kanidm/target/" && \
    sccache -s

# == Construct the orca container
FROM repos

ENV RUST_BACKTRACE=1

COPY --from=builder /usr/src/kanidm/target/release/orca /sbin/
COPY ./tools/orca/profile-sample.toml /etc/kanidm/profile-sample.toml

RUN chmod +x /sbin/orca


CMD [ "/sbin/orca", "-h" ]

