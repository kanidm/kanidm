ARG BASE_IMAGE=ekidd/rust-musl-builder:1.43.0
FROM ${BASE_IMAGE} AS builder
LABEL mantainer william@blackhats.net.au

ADD --chown=rust:rust . ./
WORKDIR kanidmd
RUN cargo build --release


FROM alpine:3.11 AS alpine
LABEL mantainer william@blackhats.net.au

RUN apk --no-cache add ca-certificates
COPY --from=builder \
    /home/rust/src/target/x86_64-unknown-linux-musl/release/kanidmd \
    /sbin/
EXPOSE 8443
VOLUME /data
CMD ["/sbin/kanidmd", "server", "-D", "/data/kanidm.db",  "-C", "/data/ca.pem", \
     "-c", "/data/cert.pem", "-k", "/data/key.pem", "--bindaddr", "0.0.0.0:8443"]

FROM scratch
LABEL mantainer william@blackhats.net.au

COPY --from=builder \
    /home/rust/src/target/x86_64-unknown-linux-musl/release/kanidmd \
    /sbin/
EXPOSE 8443
VOLUME /data
CMD ["/sbin/kanidmd", "server", "-D", "/data/kanidm.db",  "-C", "/data/ca.pem", \
     "-c", "/data/cert.pem", "-k", "/data/key.pem", "--bindaddr", "0.0.0.0:8443"]

