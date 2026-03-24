ARG BASE_IMAGE=opensuse/tumbleweed:latest

FROM ${BASE_IMAGE} AS repos
ADD scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp /zypper_fixing.sh

# ======================
FROM repos AS builder

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y \
    awk \
    libopenssl-devel \
    clang \
    make \
    sccache \
    cargo \
    pkgconf-pkg-config \
    libtalloc-devel \
    freeradius-server-devel

RUN mkdir -p /src/kanidm
COPY . /src/kanidm/

WORKDIR /src/kanidm/

# TEMPORARY
RUN cp rlm_kanidm/module/include/automask.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/connection.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/log.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/xlat.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/tmpl.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/clients.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/process.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/listen.h /usr/include/freeradius/

RUN --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo && \
    export SCCACHE_DIR=/sccache && \
    export RUSTC_WRAPPER=/usr/bin/sccache && \
    export CC="/usr/bin/clang" && \
    cargo build --locked -p rlm_kanidm --lib --release && \
    cargo build --locked -p kanidm_radiusd --bin kanidm_radiusd --release && \
    cp /src/kanidm/target/release/librlm_kanidm.so /src/kanidm/target/release/rlm_kanidm.so && \
    sccache -s

# ======================
FROM repos AS final

ARG RADIUS_USER=radiusd
EXPOSE 1812 1813
ENV KANIDM_CONFIG_FILE="/data/radius.toml"

COPY --from=builder /src/kanidm/target/release/rlm_kanidm.so /tmp/rlm_kanidm.so
COPY --from=builder /src/kanidm/target/release/kanidm_radiusd /tmp/kanidm_radiusd

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
    freeradius-client \
    freeradius-server \
    freeradius-server-utils \
    openssl && \
    rpm -e --nodeps libpython3_13-1_0 python313-base && \
    zypper clean -a


ADD  rlm_kanidm/container/mods-available/ /etc/raddb/mods-available/
COPY rlm_kanidm/container/sites-available/ /etc/raddb/sites-available/

RUN module_dir="$(for d in /usr/lib64/freeradius /usr/lib/freeradius; do [ -d "$d" ] && echo "$d" && break; done)" && \
    test -n "${module_dir}" && \
    install -m 0755 /tmp/rlm_kanidm.so "${module_dir}/rlm_kanidm.so" && \
    install -m 0755 /tmp/kanidm_radiusd /usr/local/bin/kanidm_radiusd


# Enable the native kanidm module and check-eap-tls virtual server.
RUN ln -s /etc/raddb/mods-available/kanidm_rust /etc/raddb/mods-enabled/kanidm && \
    ln -s /etc/raddb/sites-available/check-eap-tls /etc/raddb/sites-enabled/check-eap-tls

# # disable auth via methods we don't support!
RUN rm /etc/raddb/mods-available/sql && \
    rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R $RADIUS_USER:$RADIUS_USER /etc/raddb/ && \
    mkdir -p /etc/raddb/certs && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf

RUN mkdir /data && chown radiusd /data && \
    mkdir -p /etc/raddb/certs/ && chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/local/bin/kanidm_radiusd" ]

