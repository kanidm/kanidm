ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS builder
LABEL mantainer william@blackhats.net.au

RUN zypper -vv ref && \
    zypper install -y \
        cargo \
        rust \
        gcc \
        clang lld \
        make automake autoconf \
        libopenssl-devel pam-devel \
        sccache && \
    zypper clean -a

COPY . /usr/src/kanidm
WORKDIR /usr/src/kanidm/kanidmd

ARG SCCACHE_REDIS

RUN ln -s -f /usr/bin/clang /usr/bin/cc && \
    ln -s -f /usr/bin/ld.lld /usr/bin/ld

RUN if [ "$(uname -m)" == "x86_64" ]; \
		then export RUSTFLAGS='-Ctarget-cpu=haswell'; \
	fi; \
	if [ "$(uname -m)" == "aarch64" ]; \
		then export RUSTFLAGS=''; \
	fi; \
	if [ "${SCCACHE_REDIS}" != "" ]; \
		then \
			export CC="/usr/bin/sccache /usr/bin/clang" && \
			export RUSTC_WRAPPER=sccache && \
			sccache --start-server; \
		else \
			export CC="/usr/bin/clang"; \
	fi; \
	export RUSTC_BOOTSTRAP=1 && \
	echo $RUSTC_BOOTSTRAP && \
	echo $RUSTC_WRAPPER && \
	echo $RUSTFLAGS && \
	echo $CC && \
	cargo build \
		--features=concread/simd_support,libsqlite3-sys/bundled \
		--release; \
	if [ "${SCCACHE_REDIS}" != "" ]; \
		then sccache -s; \
	fi; \
	ls -al /usr/src/kanidm/target/release/


FROM ${BASE_IMAGE}
LABEL mantainer william@blackhats.net.au

RUN zypper ref && \
    zypper install -y \
        timezone \
        sqlite3 \
        pam && \
    zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-c", "/data/server.toml"]


