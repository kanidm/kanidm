ARG BASE_IMAGE=opensuse/tumbleweed:latest

FROM ${BASE_IMAGE} AS builder

ADD ../scripts/zypper_fixing.sh /zypper_fixing.sh
RUN /zypper_fixing.sh

RUN zypper install -y \
    awk \
    libopenssl-devel \
    clang \
    make \
    cargo \
    rust \
    pkgconf-pkg-config \
    libtalloc-devel \
    curl

# openSUSE's freeradius-server-devel headers are incomplete for building
# out-of-tree modules (radiusd.h includes headers not shipped by package).
# Overlay upstream 3.2.8 include set so module builds succeed.
RUN mkdir -p /tmp/freeradius-src && mkdir -p /usr/include/freeradius-devel/  && \
    curl -fsSL \
    https://github.com/FreeRADIUS/freeradius-server/archive/refs/tags/release_3_2_8.tar.gz \
    | tar -xz -C /tmp/freeradius-src && \
    mv /tmp/freeradius-src/freeradius-server-release{*,} && \
    cd /tmp/freeradius-src/freeradius-server-release && \
    ./configure --with-openssl=no > /tmp/freeradius_configure.log 2>&1 && \
    make > /tmp/freeradius_make.log 2>&1 && \
    mkdir -p /usr/include/freeradius/ && \
    cp -R ./src/include/* /usr/include/freeradius/ && \
    cp -R ./src/include/* /usr/include/freeradius-devel/

RUN mkdir -p /src/kanidm
COPY . /src/kanidm/

RUN cd /src/kanidm && \
    cargo build --quiet -p rlm_kanidm  --features freeradius-module --release && \
    cp /src/kanidm/target/release/librlm_kanidm.so /src/kanidm/target/release/rlm_kanidm.so && \
    rm -rf /tmp/freeradius-src/ && \
    zypper remove -y rust  gcc clang make pkgconf-pkg-config libtalloc-devel libopenssl-devel && \
    zypper clean -a


FROM ${BASE_IMAGE} AS final

ARG RADIUS_USER=radiusd
EXPOSE 1812 1813
ENV KANIDM_CONFIG_FILE="/data/radius.toml"

COPY --from=builder /src/kanidm/target/release/rlm_kanidm.so /tmp/rlm_kanidm.so


RUN zypper install -y \
    freeradius-client \
    freeradius-server \
    freeradius-server-utils && \
    python3 && \
    zypper clean -a


ADD unix_integration/rlm_kanidm/container/mods-available/ /etc/raddb/mods-available/
COPY unix_integration/rlm_kanidm/container/sites-available/ /etc/raddb/sites-available/

RUN module_dir="$(for d in /usr/lib64/freeradius /usr/lib/freeradius; do [ -d "$d" ] && echo "$d" && break; done)" && \
    test -n "${module_dir}" && \
    install -m 0755 /tmp/rlm_kanidm.so "${module_dir}/rlm_kanidm.so"


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


COPY rlm_python/radius_entrypoint.py /radius_entrypoint.py

RUN mkdir /data && chown radiusd /data && \
    mkdir -p /etc/raddb/certs/ && chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/bin/python3", "/radius_entrypoint.py" ]
