ARG BASE_IMAGE=opensuse/tumbleweed:latest
# FROM ${BASE_IMAGE} as repos
FROM ${BASE_IMAGE}

ADD ../scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp /zypper_fixing.sh

# ======================
# FROM repos
ARG RADIUS_USER=radiusd
EXPOSE 1812 1813
ENV KANIDM_CONFIG_FILE="/data/kanidm"

RUN --mount=type=cache,id=zypp,target=/var/cache/zypp zypper install -y \
        freeradius-client \
        freeradius-server \
        freeradius-server-python3 \
        freeradius-server-utils \
        hostname \
        python3 \
        python3-devel \
        python3-pip \
        timezone \
        iproute2 \
        iputils \
        openssl \
        curl

# Don't put in the TZ at build time - it needs to be bind mounted at runtime
# else we are forcing things on people.
# RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ADD rlm_python/mods-available/ /etc/raddb/mods-available/
COPY rlm_python/sites-available/ /etc/raddb/sites-available/

# Set a working directory of /etc/raddb
WORKDIR /etc/raddb

# Enable the python and cache module.
RUN ln -s /etc/raddb/mods-available/python3 /etc/raddb/mods-enabled/python3 && \
    ln -s /etc/raddb/sites-available/check-eap-tls /etc/raddb/sites-enabled/check-eap-tls

# disable auth via methods we don't support!
RUN rm /etc/raddb/mods-available/sql && \
    rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R $RADIUS_USER. /etc/raddb/ && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf

RUN mkdir -p /pkg/pykanidm/
COPY pykanidm/ /pkg/pykanidm/

# install the package and its dependencies
RUN python3 -m pip install \
    --break-system-packages \
    --no-cache-dir \
    --no-warn-script-location \
    /pkg/pykanidm

COPY rlm_python/radius_entrypoint.py /radius_entrypoint.py


RUN chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/bin/python3", "/radius_entrypoint.py" ]
