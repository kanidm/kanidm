# Installing the Server

Currently we have a pre-release docker image based on git master. They can be found at:

    https://hub.docker.com/r/kanidm/server
    https://hub.docker.com/r/kanidm/radius

You'll need a volume where you can put certificates and the database:

    docker volume create kanidmd

You should have a ca.pem, cert.pem and key.pem in your kanidmd volume. The reason for requiring
TLS is explained in [why tls](./why_tls.md) . To put the certificates in place you can use a shell container
that mounts the volume such as:

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/* /data/
    OR for a shell into the volume:
    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh

You will also need a config file in `/data/server.toml`. It's contents should be as follows:

    # The webserver bind address. Will use HTTPS if tls_* is provided.
    # Defaults to "127.0.0.1:8443"
    bindaddress = "127.0.0.1:8443"
    # The read-only ldap server bind address. will use LDAPS if tls_* is provided.
    # Defaults to "" (disabled)
    # ldapbindaddress = "127.0.0.1:3636"
    # The path to the kanidm database.
    db_path = "/data/kanidm.db"
    # If you have a known filesystem, kanidm can tune sqlite to match. Valid choices are:
    # [zfs, other]
    # If you are unsure about this, default to other
    # zfs:
    # * sets sqlite pagesize to 64k, you should set recordsize=64k on the zfs filesystem.
    # db_fs_type = "zfs"
    # TLS ca, certificate and key in pem format. All three must be commented, or present
    # tls_ca = "/data/ca.pem"
    # tls_cert = "/data/cert.pem"
    # tls_key = "/data/key.pem"
    # The log level of the server. May be default, verbose, perfbasic, perffull
    # Defaults to "default"
    # log_level = "default"

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd recover_account -c /data/server.toml -n admin

> **HINT**
> If you want to try the latest development releases instead, use the image tag kanidm/server:devel instead

You then want to set your domain name so that spn's are generated correctly.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd domain_name_change -c /data/server.toml -n idm.example.com

Now we can run the server so that it can accept connections. This defaults to using `-c /data/server.toml`

    docker run -p 8443:8443 -v kanidmd:/data kanidm/server:latest

# Development Version

If you are interested to run our latest code from development, you can do this by changing the
docker tag to `kanidm/server:devel`.

# Running as non-root in docker

By default the above commands will run kanidmd as "root" in the container to make the onboarding
smoother. However, this is not recommended in production for security reasons.

You should allocate a uidnumber/gidnumber for the service to run as that is unique on your host
system. In this example we use `1000:1000`

You will need to adjust the permissions on the /data volume to ensure that the process
can manage the files. Kanidm requires the ability to write to the /data directory to create
the sqlite files. This uid/gidnumber should match the above. You could consider the following
changes to help isolate these changes:

    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh
    # mkdir /data/db/
    # chown 1000:1000 /data/db/
    # chmod 750 /data/db/
    # sed -i -e "s/db_path.*/db_path = \"\/data\/db\/kanidm.db\"/g" /data/server.toml
    # chown root:root /data/server.toml
    # chmod 644 /data/server.toml

You can then use this with run the kanidm server in docker with a user.

    docker run --rm -i -t -u 1000:1000 -v kanidmd:/data kanidm/server:latest /sbin/kanidmd ...

> **HINT**
> You need to use the uidnumber/gidnumber to the `-u` argument, as the container can't resolve
> usernames from the host system.


