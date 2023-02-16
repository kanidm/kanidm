# This builds the kanidm CLI tools
ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper dup -y

FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE
ARG KANIDM_BUILD_OPTIONS=""

RUN echo Profile $KANIDM_BUILD_PROFILE
RUN echo Features $KANIDM_FEATURES

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
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

RUN mkdir -p /usr/src/kanidm/.cargo
RUN cp /usr/src/kanidm/cargo_vendor_config /usr/src/kanidm/.cargo/config.toml

WORKDIR /usr/src/kanidm/

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.mold"

# build the CLI
RUN export CC="/usr/bin/clang"; \
if [ -z "${KANIDM_FEATURES}" ]; then \
  cargo build -p kanidm_tools ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --release; \
  cargo build -p kanidm-ipa-sync ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --release; \
else \
  cargo build -p kanidm_tools ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --features="${KANIDM_FEATURES}" \
    --release; \
  cargo build -p kanidm-ipa-sync ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --features="${KANIDM_FEATURES}" \
    --release; \
fi

RUN ls -al /usr/src/kanidm/target/release

# == Construct the tools container
FROM repos

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y timezone busybox-adduser openssl-3

COPY --from=builder /usr/src/kanidm/target/release/kanidm /sbin/
COPY --from=builder /usr/src/kanidm/target/release/kanidm-ipa-sync /sbin/
RUN chmod +x /sbin/kanidm
RUN chmod +x /sbin/kanidm-ipa-sync
ENV RUST_BACKTRACE 1

RUN adduser -D -H kanidm
RUN mkdir /etc/kanidm && \
    touch /etc/kanidm/config

USER kanidm

CMD [ "/sbin/kanidm", "-h" ]

