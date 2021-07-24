## Configuring the Server

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
    #   - WriteReplica
    #     This server provides all functionality of Kanidm. It allows authentication, writes, and
    #     the web user interface to be served.
    #   - WriteReplicaNoUI
    #     This server is the same as a WriteReplica, but does NOT offer the web user interface.
    #   - ReadOnlyReplica
    #     This server will not writes initiated by clients. It supports authentication and reads,
    #     and must have a replication agreement as a source of it's data.
    #   Defaults to "WriteReplica".
    # role = "WriteReplica"

An example is located in [examples/server.toml](../../examples/server.toml).

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd recover_account -c /data/server.toml -n admin

You then want to set your domain name so that security principal names (spn's) are generated correctly.
This domain name *must* match the url/origin of the server that you plan to use to interact with
so that other features work correctly. It is possible to change this domain name later.

    docker run --rm -i -t -v kanidmd:/data kanidm/server:latest /sbin/kanidmd domain_name_change -c /data/server.toml -n idm.example.com

Now we can run the server so that it can accept connections. This defaults to using `-c /data/server.toml`

    docker run -p 8443:8443 -v kanidmd:/data kanidm/server:latest