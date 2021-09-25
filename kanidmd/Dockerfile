ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS builder
LABEL mantainer william@blackhats.net.au

RUN zypper ar obs://devel:languages:rust devel:languages:rust && \
    zypper --gpg-auto-import-keys ref --force && \
    zypper dup -y && \
    zypper install -y \
        cargo \
        rust \
        gcc \
        clang lld \
        make automake autoconf \
        libopenssl-devel pam-devel \
        sqlite3-devel \
        sccache && \
    zypper clean -a

COPY . /usr/src/kanidm
WORKDIR /usr/src/kanidm/kanidmd

ARG SCCACHE_REDIS
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE

RUN mkdir /scratch && \
	ln -s -f /usr/bin/clang /usr/bin/cc && \
	ln -s -f /usr/bin/ld.lld /usr/bin/ld && \
	if [ "${SCCACHE_REDIS}" != "" ]; \
		then \
			export CC="/usr/bin/sccache /usr/bin/clang" && \
			export RUSTC_WRAPPER=sccache && \
			sccache --start-server; \
		else \
			export CC="/usr/bin/clang"; \
	fi && \
	export RUSTC_BOOTSTRAP=1 && \
	echo $KANIDM_BUILD_PROFILE && \
	echo $KANIDM_FEATURES && \
	CARGO_HOME=/scratch/.cargo cargo build \
		--features=${KANIDM_FEATURES} \
		--target-dir=/usr/src/kanidm/target/ \
		--release && \
	ls -al /usr/src/kanidm/target/release/ && \
	if [ "${SCCACHE_REDIS}" != "" ]; \
		then sccache -s; \
	fi;

FROM ${BASE_IMAGE}
LABEL mantainer william@blackhats.net.au

RUN zypper ref && \
    zypper dup -y && \
    zypper install -y \
        timezone \
        sqlite3 \
        pam && \
    zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/
COPY --from=builder /usr/src/kanidm/kanidmd_web_ui/pkg /pkg

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-c", "/data/server.toml"]

