FROM opensuse/tumbleweed:latest

EXPOSE 1812 1813

RUN zypper --gpg-auto-import-keys refresh --force
RUN zypper install -y \
    freeradius-client \
    freeradius-server \
    freeradius-server-ldap \
    freeradius-server-python3 \
    freeradius-server-utils \
    openldap2-client \
    hostname \
    python3 \
    python3-devel \
    python3-pip \
    timezone \
    iproute2 \
    iputils \
    curl

RUN zypper clean


# Copy the python module to /etc/raddb
# COPY kanidmradius.py /etc/raddb/


# Copy in the python changes, as well as the default/inner-tunnel changes
COPY kanidm_rlm_python/mod-python3 /etc/raddb/mods-available/python3
COPY kanidm_rlm_python/eap /etc/raddb/mods-available/eap
COPY kanidm_rlm_python/cache /etc/raddb/mods-available/cache
COPY kanidm_rlm_python/default /etc/raddb/sites-available/default
COPY kanidm_rlm_python/inner-tunnel /etc/raddb/sites-available/inner-tunnel

# Set a working directory of /etc/raddb
WORKDIR /etc/raddb
# /data volume
# VOLUME /data

# Enable the python and cache module.
RUN ln -s ../mods-available/python3 /etc/raddb/mods-enabled/python3
#RUN ln -s ../mods-available/cache /etc/raddb/mods-enabled/cache
# disable auth via methods we don't support!
RUN rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R radiusd: /etc/raddb
RUN chmod 775 /etc/raddb/certs
RUN chmod 640 /etc/raddb/clients.conf

# install the packages
RUN mkdir -p /pkg/kanidmradius/kanidmradius/
COPY kanidm_rlm_python//kanidmradius/ /pkg/kanidmradius/kanidmradius/
COPY kanidm_rlm_python/pyproject.toml /pkg/kanidmradius/

RUN mkdir -p /pkg/pykanidm/
COPY pykanidm/ /pkg/pykanidm/

# install the package and its dependencies
RUN ln -s /etc/raddb/mods-config/python3/radiusd.py /usr/lib/python3.8/site-packages/
RUN python3 -m pip install --no-cache-dir --no-warn-script-location /pkg/pykanidm
RUN python3 -m pip install --no-cache-dir --no-warn-script-location /pkg/kanidmradius
# clean up after install
RUN rm -rf /pkg/*


USER radiusd

COPY kanidm_rlm_python/entrypoint.py /entrypoint.py
CMD [ "/usr/bin/python3", "/entrypoint.py" ]
