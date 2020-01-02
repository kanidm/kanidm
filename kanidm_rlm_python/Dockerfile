FROM opensuse/leap:latest
MAINTAINER william@blackhats.net.au

EXPOSE 1812 1813

RUN zypper install -y timezone freeradius-client freeradius-server freeradius-server-ldap \
    freeradius-server-python openldap2-client freeradius-server-utils hostname \
    python2 python2-requests && \
    zypper clean

# Copy the python module to /etc/raddb
COPY kanidmradius.py /etc/raddb/
COPY entrypoint.py /entrypoint.py

# Copy in the python changes, as well as the default/inner-tunnel changes
COPY mod-python /etc/raddb/mods-available/python
COPY eap /etc/raddb/mods-available/eap
COPY cache /etc/raddb/mods-available/cache
COPY default /etc/raddb/sites-available/default
COPY inner-tunnel /etc/raddb/sites-available/inner-tunnel

# Enable the python and cache module.
RUN ln -s ../mods-available/python /etc/raddb/mods-enabled/python
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
CMD [ "/usr/bin/python2", "/entrypoint.py" ]
