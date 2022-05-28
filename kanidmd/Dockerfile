ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
RUN zypper dup -y
# To help mirrors not be as bad
RUN zypper install -y mirrorsorcerer
RUN /usr/sbin/mirrorsorcerer -x; true
RUN zypper refresh --force
RUN zypper dup -y

FROM repos AS builder
LABEL maintainer william@blackhats.net.au

RUN zypper install -y \
        cargo \
        rust \
        gcc clang lld \
        make automake autoconf \
        libopenssl-devel pam-devel \
        sqlite3-devel \
        sccache && \
    zypper clean -a

COPY . /usr/src/kanidm
WORKDIR /usr/src/kanidm/kanidmd/daemon

ARG SCCACHE_REDIS
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE

RUN mkdir /scratch
RUN echo $KANIDM_BUILD_PROFILE
RUN echo $KANIDM_FEATURES

ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.lld"
ENV CARGO_HOME=/scratch/.cargo

RUN if [ "${SCCACHE_REDIS}" != "" ]; \
		then \
			export CC="/usr/bin/sccache /usr/bin/clang" && \
			export RUSTC_WRAPPER=sccache && \
			sccache --start-server; \
		else \
			export CC="/usr/bin/clang"; \
	fi && \
    cargo build \
		--features=${KANIDM_FEATURES} \
		--target-dir=/usr/src/kanidm/target/ \
		--release && \
    if [ "${SCCACHE_REDIS}" != "" ]; \
		then sccache -s; \
	fi;

RUN ls -al /usr/src/kanidm/target/release

FROM repos
LABEL maintainer william@blackhats.net.au

RUN zypper install -y \
        timezone \
        sqlite3 \
        pam
RUN zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/
COPY --from=builder /usr/src/kanidm/kanidmd_web_ui/pkg /pkg

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-c", "/data/server.toml"]
