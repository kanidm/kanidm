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

