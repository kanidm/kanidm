ARG BASE_IMAGE=opensuse/tumbleweed@sha256:211becaf2c9250ae36eb313abf5db38cd5e159cac2d920e1ef7bb62429a51585
FROM ${BASE_IMAGE} AS builder
LABEL mantainer william@blackhats.net.au

RUN zypper mr -d repo-non-oss && \
    zypper mr -d repo-oss && \
    zypper mr -d repo-update && \
    zypper ar https://download.opensuse.org/update/tumbleweed/ repo-update-https && \
    zypper ar https://download.opensuse.org/tumbleweed/repo/oss/ repo-oss-https && \
    zypper ar https://download.opensuse.org/tumbleweed/repo/non-oss/ repo-non-oss-https && \
    zypper ref && \
    zypper install -y \
        cargo \
        rust \
        gcc \
        automake \
        autoconf \
        make \
        libopenssl-devel \
        pam-devel && \
    zypper clean -a

COPY . /usr/src/kanidm
WORKDIR /usr/src/kanidm

RUN cargo build --release

FROM ${BASE_IMAGE}
LABEL mantainer william@blackhats.net.au

RUN zypper mr -d repo-non-oss && \
    zypper mr -d repo-oss && \
    zypper mr -d repo-update && \
    zypper ar https://download.opensuse.org/update/tumbleweed/ repo-update-https && \
    zypper ar https://download.opensuse.org/tumbleweed/repo/oss/ repo-oss-https && \
    zypper ar https://download.opensuse.org/tumbleweed/repo/non-oss/ repo-non-oss-https && \
    zypper ref && \
    zypper install -y \
        timezone \
        pam && \
    zypper clean -a

COPY --from=builder /home/kanidm/target/release/kanidmd /sbin/

EXPOSE 8443
VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-D", "/data/kanidm.db",  "-C", "/data/ca.pem", \
     "-c", "/data/cert.pem", "-k", "/data/key.pem", "--bindaddr", "0.0.0.0:8443"]

