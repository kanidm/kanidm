FROM opensuse/tumbleweed:latest
MAINTAINER william@blackhats.net.au

EXPOSE 8080

COPY . /home/kanidm/

WORKDIR /home/kanidm/

RUN zypper install -y timezone cargo rust gcc sqlite3-devel libopenssl-devel && \
    RUSTC_BOOTSTRAP=1 cargo build --release && \
    zypper rm -u -y cargo rust gcc && \
    zypper clean

RUN cd /etc && \
    ln -sf ../usr/share/zoneinfo/Australia/Brisbane localtime

VOLUME /data

ENV RUST_BACKTRACE 1
CMD ["/home/kanidm/target/release/kanidmd", "server", "-D", "/data/kanidm.db",  "-C", "/data/ca.pem", "-c", "/data/cert.pem", "-k", "/data/key.pem", "--bindaddr", "0.0.0.0:8080"]

