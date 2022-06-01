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
COPY mod-python3 /etc/raddb/mods-available/python3
COPY eap /etc/raddb/mods-available/eap
COPY cache /etc/raddb/mods-available/cache
COPY default /etc/raddb/sites-available/default
COPY inner-tunnel /etc/raddb/sites-available/inner-tunnel


# Set a working directory of /etc/raddb
WORKDIR /etc/raddb
# /data volume
VOLUME /data


# Enable the python and cache module.
RUN ln -s ../mods-available/python3 /etc/raddb/mods-enabled/python3
#RUN ln -s ../mods-available/cache /etc/raddb/mods-enabled/cache
# disable auth via methods we don't support!
RUN rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows radiusd (?) to write to the directory
RUN chown -R radiusd: /etc/raddb
RUN chmod 775 /etc/raddb/certs
RUN chmod 640 /etc/raddb/clients.conf

RUN mkdir -p /tmp/kanidmradius/
COPY ./kanidmradius/ /tmp/kanidmradius/
COPY pyproject.toml /tmp/

RUN python3 -m pip install --no-cache-dir --no-warn-script-location /tmp/
USER radiusd
# install the package and its dependencies
# RUN python3 -m pip install requests toml
# just yeet it into the right place
USER root
# RUN mkdir -p /etc/raddb/mods-config/python3/kanidmradius/
# COPY ./kanidmradius/ /etc/raddb/mods-config/python3/kanidmradius
RUN rm -rf /tmp/*

RUN ln -s /etc/raddb/mods-config/python3/radiusd.py /usr/lib/python3.8/site-packages/

USER radiusd

COPY entrypoint.py /entrypoint.py
CMD [ "/usr/bin/python3", "/entrypoint.py" ]
