FROM opensuse/tumbleweed:latest AS builder
MAINTAINER william@blackhats.net.au

RUN zypper install -y timezone cargo rust gcc sqlite3-devel libopenssl-devel
COPY . /home/kanidm/
WORKDIR /home/kanidm/
RUN cargo build --release

FROM opensuse/tumbleweed:latest

EXPOSE 8080
WORKDIR /
COPY --from=builder /home/kanidm/target/release/kanidmd /sbin/
RUN zypper install -y sqlite3 openssl

VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/sbin/kanidmd", "server", "-D", "/data/kanidm.db",  "-C", "/data/ca.pem", "-c", "/data/cert.pem", "-k", "/data/key.pem", "--bindaddr", "0.0.0.0:8080"]

