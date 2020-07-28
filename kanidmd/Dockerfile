ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS builder
LABEL mantainer william@blackhats.net.au

RUN zypper ref && \
    zypper install -y \
        cargo \
        rust \
        gcc \
        clang lld \
        make automake autoconf \
        libopenssl-devel pam-devel && \
    zypper clean -a


COPY . /usr/src/kanidm
WORKDIR /usr/src/kanidm/kanidmd

RUN ln -s -f /usr/bin/clang /usr/bin/cc && \
    ln -s -f /usr/bin/ld.lld /usr/bin/ld

RUN CC=/usr/bin/clang RUSTC_BOOTSTRAP=1 cargo build --features=concread/simd_support --release

FROM ${BASE_IMAGE}
LABEL mantainer william@blackhats.net.au

RUN zypper ref && \
    zypper install -y \
        timezone \
        pam && \
    zypper clean -a

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-c", "/data/server.toml"]


