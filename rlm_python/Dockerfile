FROM freeradius/freeradius-server:latest
EXPOSE 1812 1813
ARG RADIUS_USER=freerad
ENV TZ=Etc/UTC
# These all need to be on one line else the cache ends up in the layers.
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
    freeradius-utils \
    hostname \
    python3 \
    python3-pip \
    python-is-python3 \
    tzdata \
    iproute2 \
    iputils-ping iputils-tracepath \
    openssl \
    curl

ADD  rlm_python/mods-available/ /etc/raddb/mods-available/
COPY rlm_python/sites-available/ /etc/raddb/sites-available/

# Set a working directory of /etc/raddb
WORKDIR /etc/raddb

# Enable the python and cache module.
RUN ln -s /etc/raddb/mods-available/python3 /etc/raddb/mods-enabled/python3 && \
    ln -s /etc/raddb/sites-available/check-eap-tls /etc/raddb/sites-enabled/check-eap-tls

# disable auth via methods we don't support!
# RUN rm /etc/raddb/mods-available/sql && \
    # rm /etc/raddb/mods-enabled/{passwd,totp}


# Allows the radiusd user to write to the directory
RUN chown -R $RADIUS_USER. /etc/raddb && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf

RUN mkdir -p /pkg/pykanidm/
COPY pykanidm/ /pkg/pykanidm/

# install the package and its dependencies
RUN python3 -m pip install --no-cache-dir --no-warn-script-location /pkg/pykanidm && \
    rm -rf /pkg/*

COPY rlm_python/radius_entrypoint.py /radius_entrypoint.py

ENV LD_PRELOAD=/usr/lib64/libpython3.so
ENV KANIDM_CONFIG_FILE="/data/kanidm"

RUN chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/bin/python3", "/radius_entrypoint.py" ]
