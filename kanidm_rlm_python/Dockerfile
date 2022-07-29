FROM opensuse/tumbleweed:latest

EXPOSE 1812 1813

# These all need to be on one line else the rpm cache ends
# up in the layers.
RUN zypper refresh --force && \
    zypper install -y \
    freeradius-client \
    freeradius-server \
    freeradius-server-python3 \
    freeradius-server-utils \
    hostname \
    python310 \
    python310-devel \
    python310-pip \
    timezone \
    iproute2 \
    iputils \
    openssl \
    curl && \
    zypper clean

ADD kanidm_rlm_python/mods-available/ /etc/raddb/mods-available/
COPY kanidm_rlm_python/sites-available/ /etc/raddb/sites-available/

# Set a working directory of /etc/raddb
WORKDIR /etc/raddb

# Enable the python and cache module.
RUN ln -s /etc/raddb/mods-available/python3 /etc/raddb/mods-enabled/python3

# disable auth via methods we don't support!
RUN rm /etc/raddb/mods-available/sql
RUN rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R radiusd: /etc/raddb
RUN chmod 775 /etc/raddb/certs
RUN chmod 640 /etc/raddb/clients.conf

# install the packages
RUN mkdir -p /pkg/kanidmradius/kanidmradius/
COPY kanidm_rlm_python/kanidmradius/ /pkg/kanidmradius/kanidmradius/
COPY kanidm_rlm_python/pyproject.toml /pkg/kanidmradius/

RUN mkdir -p /pkg/pykanidm/
COPY pykanidm/ /pkg/pykanidm/

# install the package and its dependencies
RUN python3 -m pip install --no-cache-dir --no-warn-script-location /pkg/pykanidm
RUN python3 -m pip install --no-cache-dir --no-warn-script-location /pkg/kanidmradius
# clean up after install
RUN rm -rf /pkg/*

USER radiusd

COPY kanidm_rlm_python/entrypoint.py /entrypoint.py
CMD [ "/usr/bin/python3", "/entrypoint.py" ]
