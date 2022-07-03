# This builds the kanidm CLI tool

ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
# To help mirrors not be as bad
RUN zypper install -y mirrorsorcerer
RUN /usr/sbin/mirrorsorcerer -x; true
RUN zypper refresh --force
RUN zypper dup -y

FROM repos AS builder

RUN zypper install -y \
        cargo \
        gcc \
        rust wasm-pack \
        clang lld \
        make automake autoconf \
        libopenssl-devel \
        pam-devel \
        libudev-devel \
        sqlite3-devel \
        sccache \
        rsync
RUN zypper clean -a

COPY . /usr/src/kanidm

ARG SCCACHE_REDIS=""
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE
ARG KANIDM_BUILD_OPTIONS=""

RUN mkdir /scratch
RUN echo $KANIDM_BUILD_PROFILE
RUN echo $KANIDM_FEATURES

ENV CARGO_HOME=/scratch/.cargo
ENV RUSTFLAGS="-Clinker=clang"

WORKDIR /usr/src/kanidm/

ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.lld"

RUN if [ "${SCCACHE_REDIS}" != "" ]; \
then \
  export CARGO_INCREMENTAL=false && \
  export CC="/usr/bin/sccache /usr/bin/clang" && \
  export RUSTC_WRAPPER=sccache && \
  sccache --start-server; \
else \
  export CC="/usr/bin/clang"; \
fi

# build the CLI
RUN if [ -z "${KANIDM_FEATURES}" ]; then \
  cargo build -p kanidm_tools --bin kanidm ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --release; \
else \
  cargo build -p kanidm_tools --bin kanidm ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --features="${KANIDM_FEATURES}" \
    --release; \
fi

RUN if [ "${SCCACHE_REDIS}" != "" ]; then sccache -s; fi

RUN ls -al /usr/src/kanidm/target/release

FROM repos

RUN zypper install -y timezone
#         # sqlite3 \
#         pam
RUN zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidm /sbin/
RUN chmod +x /sbin/kanidm
ENV RUST_BACKTRACE 1

ENTRYPOINT [ "/sbin/kanidm" ]

