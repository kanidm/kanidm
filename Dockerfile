FROM opensuse/tumbleweed:latest
MAINTAINER william@blackhats.net.au

COPY . /home/rsidm/

WORKDIR /home/rsidm/

RUN zypper install -y timezone cargo rust rust-std gcc && \
    RUSTC_BOOTSTRAP=1 cargo build --release && \
    zypper rm -u -y cargo rust rust-std gcc && \
    zypper clean

RUN cd /etc && \
    ln -sf ../usr/share/zoneinfo/Australia/Brisbane localtime

RUN useradd -m -r rsidm
USER rsidm

ENV RUST_BACKTRACE 1
CMD ["/home/rsidm/target/release/rsidm"]

