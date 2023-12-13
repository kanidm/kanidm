# Configuring the Server

In this section we will configure your server and create it's container instance.

## Configuring server.toml

You need a configuration file in the volume named `server.toml`. (Within the container it should be
`/data/server.toml`) The following is a commented example configuration.

The full options and explanations are in the
[kanidmd_core::config::ServerConfig](https://kanidm.github.io/kanidm/master/rustdoc/kanidmd_core/config/struct.ServerConfig.html)
for your particular build.

```toml
{{#rustdoc_include ../../examples/server_container.toml}}
```

This example is located in
[examples/server_container.toml](https://github.com/kanidm/kanidm/blob/master/examples/server_container.toml).

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=Warning!
text=You MUST set the `domain` name correctly, aligned with your `origin`, else the server may refuse to start or some features (e.g. webauthn, oauth) may not work correctly!
}}

<!-- deno-fmt-ignore-end -->

### Check the configuration is valid

You should test your configuration is valid before you proceed. This defaults to using
`-c /data/server.toml`.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd configtest
```

## Run the Server

Now we can run the server so that it can accept connections. This defaults to using
`-c /data/server.toml`.

```bash
docker run -p 443:8443 -v kanidmd:/data kanidm/server:latest
```

### Using the NET\_BIND\_SERVICE capability

If you plan to run without using docker port mapping or some other reverse proxy, and your
bindaddress or ldapbindaddress port is less than `1024` you will need the `NET_BIND_SERVICE` in
docker to allow these port binds. You can add this with `--cap-add` in your docker run command.

```bash
docker run --cap-add NET_BIND_SERVICE --network [host OR macvlan OR ipvlan] \
    -v kanidmd:/data kanidm/server:latest
```

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-alert.md
imagepath=images
title=Tip
text=However you choose to run your server, you should document and keep note of the docker run / create command you chose to start the instance. This will be used in the upgrade procedure.
}}

<!-- deno-fmt-ignore-end -->

### Default Admin Accounts

Now that the server is running, you can initialise the default admin accounts. There are two
parallel admin accounts that have seperate functions. `admin` which manages Kanidm's configuration,
and `idm_admin` which manages accounts and groups in Kanidm.

You should consider these as "break-glass" accounts. They exist to allow the server to be
bootstrapped and accessed in emergencies. They are not intended for day-to-day use.

This command will generate a new random password for the admin accounts. You must run this command
as the same user as the kanidmd process or as root. This defaults to using `-c /data/server.toml`.

```bash
docker exec -i -t <container name> \
  kanidmd recover-account admin
#  new_password: "xjgG4..."
```

```bash
docker exec -i -t <container name> \
  kanidmd recover-account idm_admin
#  new_password: "9Eux1..."
```
