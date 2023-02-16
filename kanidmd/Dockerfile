# Build the main Kanidmd server
ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper dup -y

# ======================
FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE="container_generic"
ARG KANIDM_BUILD_OPTIONS=""

RUN echo Profile $KANIDM_BUILD_PROFILE
RUN echo Features $KANIDM_FEATURES

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
        cargo \
        clang \
        make automake autoconf \
        libopenssl-3-devel pam-devel \
        sqlite3-devel \
        rsync \
        findutils \
        which \
        mold

COPY . /usr/src/kanidm

RUN mkdir -p /usr/src/kanidm/.cargo
RUN cp /usr/src/kanidm/cargo_vendor_config /usr/src/kanidm/.cargo/config.toml

# ======================

# WORKDIR /usr/src/kanidm/kanidmd_web_ui
# # This can't be used in the wasm build for now.
# # ENV RUSTFLAGS="-Clinker=clang"
# RUN ./build_wasm.sh

# ======================

WORKDIR /usr/src/kanidm/kanidmd/daemon

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.mold"

# Exports don't persist through RUN statements.
RUN export CC="/usr/bin/clang"; \
if [ -z "${KANIDM_FEATURES}" ]; then \
  cargo build -p daemon ${KANIDM_BUILD_OPTIONS} \
    --locked --offline \
    --target-dir="/usr/src/kanidm/target/" \
    --release; \
else \
  cargo build -p daemon ${KANIDM_BUILD_OPTIONS} \
    --locked --offline \
    --target-dir="/usr/src/kanidm/target/" \
    --features="${KANIDM_FEATURES}" \
    --release; \
fi

RUN ls -al /usr/src/kanidm/target/release

# ======================

FROM repos

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y \
        timezone \
        openssl-3 \
        sqlite3 \
        pam

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/
COPY --from=builder /usr/src/kanidm/kanidmd_web_ui/pkg /pkg
RUN chmod +x /sbin/kanidmd

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD [ "/sbin/kanidmd", "server", "-c", "/data/server.toml"]
