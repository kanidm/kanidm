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
        rust wasm-pack \
        clang lld \
        make automake autoconf \
        libopenssl-devel pam-devel \
        sqlite3-devel \
        sccache \
        gcc \
        rsync \
        which
RUN zypper clean -a

COPY . /usr/src/kanidm

ARG SCCACHE_REDIS=""
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE="container_generic"
ARG KANIDM_BUILD_OPTIONS=""

RUN mkdir /scratch
RUN echo $KANIDM_BUILD_PROFILE
RUN echo $KANIDM_FEATURES

# Set the build profile
ENV KANIDM_BUILD_PROFILE="${KANIDM_BUILD_PROFILE}"

ENV CARGO_HOME=/scratch/.cargo
ENV RUSTFLAGS="-Clinker=clang"

WORKDIR /usr/src/kanidm/kanidmd_web_ui
RUN if [ "${SCCACHE_REDIS}" != "" ]; \
        then \
            export CARGO_INCREMENTAL=false && \
            export RUSTC_WRAPPER=sccache && \
            sccache --start-server; \
    fi && \
    ./build_wasm.sh

WORKDIR /usr/src/kanidm/kanidmd/daemon

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

RUN if [ -z "${KANIDM_FEATURES}" ]; then \
  cargo build -p daemon ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --release; \
else \
  cargo build -p daemon ${KANIDM_BUILD_OPTIONS} \
    --target-dir="/usr/src/kanidm/target/" \
    --features="${KANIDM_FEATURES}" \
    --release; \
fi
RUN if [ "${SCCACHE_REDIS}" != "" ]; then sccache -s; fi

RUN ls -al /usr/src/kanidm/target/release

FROM repos

RUN zypper install -y \
        timezone \
        sqlite3 \
        pam
RUN zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/
COPY --from=builder /usr/src/kanidm/kanidmd_web_ui/pkg /pkg
RUN chmod +x /sbin/kanidmd

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD [ "/sbin/kanidmd", "server", "-c", "/data/server.toml"]
