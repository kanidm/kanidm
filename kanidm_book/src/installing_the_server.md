# Installing the Server

Currently we have docker images for the server components. They can be found at:

    https://hub.docker.com/r/kanidm/server
    https://hub.docker.com/r/kanidm/radius

You can fetch these with:

    docker pull kanidm/server:latest
    docker pull kanidm/radius:latest

If you wish to use an x86\_64 cpu-optimised version (See System Requirements CPU), you should use:

    docker pull kanidm/server:x86_64_latest

You may need to adjust your example commands throughout this document to suit.

## System Requirements

### CPU

If you are using the x86\_64 cpu-optimised version, you must have a CPU that is from 2013 or newer
(Haswell, Ryzen). The following instruction flags are used.

    cmov, cx8, fxsr, mmx, sse, sse2, cx16, sahf, popcnt, sse3, sse4.1, sse4.2, avx, avx2,
    bmi, bmi2, f16c, fma, lzcnt, movbe, xsave

Older or unsupported CPU's may raise a SIGIL (Illegal Instruction) on hardware that is not supported
by the project.

In this case, you should use the standard server:latest image.

In the future we may apply a baseline of flags as a requirement for x86\_64 for the server:latest
image. These flags will be:

    cmov, cx8, fxsr, mmx, sse, sse2

### Memory

Kanidm extensively uses memory caching, trading memory consumption to improve parallel throughput.
You should expect to see 64KB of ram per entry in your database, depending on cache tuning and settings.

### Disk

You should expect to use up to 8KB of disk per entry you plan to store. At an estimate 10,000 entry
databases will consume 40MB, 100,000 entry will consume 400MB.

For best performance, you should use NVME or other Flash media.

## TLS

You'll need a volume where you can place configuration, certificates, and the database:

    docker volume create kanidmd

You should have a chain.pem and key.pem in your kanidmd volume. The reason for requiring
TLS is explained in [why tls](./why_tls.md). In summary, TLS is our root of trust between the
server and clients, and a critical element of ensuring a secure system.

The key.pem should be a single PEM private key, with no encryption. The file content should be
similar to:

    -----BEGIN RSA PRIVATE KEY-----
    MII...<base64>
    -----END RSA PRIVATE KEY-----

The chain.pem is a series of PEM formatted certificates. The leaf certificate, or the certificate
that matches the private key should be the first certificate in the file. This should be followed
by the series of intermediates, and the final certificate should be the CA root. For example:

    -----BEGIN CERTIFICATE-----
    <leaf certificate>
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    <intermediate certificate>
    -----END CERTIFICATE-----
    [ more intermediates if needed ]
    -----BEGIN CERTIFICATE-----
    <ca/croot certificate>
    -----END CERTIFICATE-----

> **HINT**
> If you are using Let's Encrypt the provided files "fullchain.pem" and "privkey.pem" are already
> correctly formatted as required for Kanidm.

You can validate that the leaf certificate matches the key with the command:

    # openssl rsa -noout -modulus -in key.pem | openssl sha1
    d2188932f520e45f2e76153fbbaf13f81ea6c1ef
    # openssl x509 -noout -modulus -in chain.pem | openssl sha1
    d2188932f520e45f2e76153fbbaf13f81ea6c1ef

If your chain.pem contains the CA certificate, you can validate this file with the command:

    openssl verify -CAfile chain.pem chain.pem

If your chain.pem does not contain the CA certificate (Let's Encrypt chains do not contain the CA
for example) then you can validate with this command.

    openssl verify -untrusted fullchain.pem fullchain.pem

> **NOTE** Here "-untrusted" flag means a list of further certificates in the chain to build up
> to the root is provided, but that the system CA root should be consulted. Verification is NOT bypassed
> or allowed to be invalid.

If these verifications pass you can now use these certificates with Kanidm. To put the certificates
in place you can use a shell container that mounts the volume such as:

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/* /data/

If the above command says: `cp: cannot stat /work/*: No such file or directory`, you can instead run the following:

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/key.pem /data/
    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/chain.pem /data/

OR for a shell into the volume:

    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh

## Configuration

You will also need a config file in the volume named `server.toml` (Within the container it should be `/data/server.toml`). Its contents should be as follows:

    #   The webserver bind address. Will use HTTPS if tls_* is provided.
    #   Defaults to "127.0.0.1:8443"
    bindaddress = "127.0.0.1:8443"
    #
    #   The read-only ldap server bind address. The server will use LDAPS if tls_* is provided.
    #   Defaults to "" (disabled)
    # ldapbindaddress = "127.0.0.1:3636"
    #
    #   The path to the kanidm database.
    db_path = "/data/kanidm.db"
    #
    #   If you have a known filesystem, kanidm can tune sqlite to match. Valid choices are:
    #   [zfs, other]
    #   If you are unsure about this leave it as the default (other). After changing this
    #   value you must run a vacuum task.
    #   - zfs:
    #     * sets sqlite pagesize to 64k. You must set recordsize=64k on the zfs filesystem.
    #   - other:
    #     * sets sqlite pagesize to 4k, matching most filesystems block sizes.
    # db_fs_type = "zfs"
    #
    #   The number of entries to store in the in-memory cache. Minimum value is 256. If unset
    #   an automatic heuristic is used to scale this.
    # db_arc_size = 2048
    #
    #   TLS chain and key in pem format. Both must be commented, or both must be present
    # tls_chain = "/data/chain.pem"
    # tls_key = "/data/key.pem"
    #
    #   The log level of the server. May be default, verbose, perfbasic, perffull
    #   Defaults to "default"
    # log_level = "default"
    #
    #   The origin for webauthn. This is the url to the server, with the port included if
    #   it is non-standard (any port except 443)
    # origin = "https://idm.example.com"
    origin = "https://idm.example.com:8443"
    #
    #   The role of this server. This affects features available and how replication may interact.
    #   Valid roles are:
    #   - write_replica
    #     This server provides all functionality of Kanidm. It allows authentication, writes, and
    #     the web user interface to be served.
    #   - write_replica_no_ui
    #     This server is the same as a write_replica, but does NOT offer the web user interface.
    #   - read_only_replica
    #     This server will not writes initiated by clients. It supports authentication and reads,
    #     and must have a replication agreement as a source of it's data.
    #   Defaults to "write_replica".
    # role = "write_replica"

An example is located in [examples/server.toml](../../examples/server.toml).

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd recover_account -c /data/server.toml -n admin

You then want to set your domain name so that security principal names (spn's) are generated correctly.
This domain name *must* match the url/origin of the server that you plan to use to interact with
so that other features work correctly. It is possible to change this domain name later.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd domain_name_change -c /data/server.toml -n idm.example.com

Now we can run the server so that it can accept connections. This defaults to using `-c /data/server.toml`

    docker run -p 8443:8443 -v kanidmd:/data kanidm/server:latest

# Development Version

If you are interested to run our latest code from development, you can do this by changing the
docker tag to `kanidm/server:devel` or `kanidm/server:x86_64_v3_devel` instead.

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


