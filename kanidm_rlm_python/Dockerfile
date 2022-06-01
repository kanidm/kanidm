FROM opensuse/leap:latest
LABEL org.opencontainers.image.authors="william@blackhats.net.au"

EXPOSE 1812 1813

RUN zypper --gpg-auto-import-keys ref --force
RUN zypper refresh
RUN zypper install -y timezone freeradius-client freeradius-server freeradius-server-ldap \
    freeradius-server-python3 openldap2-client freeradius-server-utils hostname \
    python3 python3-requests python3-devel \
    iproute2 iputils curl && \
    zypper clean

# Copy the python module to /etc/raddb
COPY kanidmradius.py /etc/raddb/
COPY entrypoint.py /entrypoint.py

# Copy in the python changes, as well as the default/inner-tunnel changes
COPY mod-python3 /etc/raddb/mods-available/python3
COPY eap /etc/raddb/mods-available/eap
COPY cache /etc/raddb/mods-available/cache
COPY default /etc/raddb/sites-available/default
COPY inner-tunnel /etc/raddb/sites-available/inner-tunnel

# Enable the python and cache module.
RUN ln -s ../mods-available/python3 /etc/raddb/mods-enabled/python3
# RUN ln -s ../mods-available/cache /etc/raddb/mods-enabled/cache

# Allows radiusd (?) to write to the directory
RUN chown -R radiusd: /etc/raddb && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf


# Set a working directory of /etc/raddb
WORKDIR /etc/raddb

# /data volume
VOLUME /data

USER radiusd
CMD [ "/usr/bin/python3", "/entrypoint.py" ]
