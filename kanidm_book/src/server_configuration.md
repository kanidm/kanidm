# Configuring the Server

## Configuring server.toml

You need a configuration file in the volume named `server.toml`. (Within the container it should be
`/data/server.toml`) Its contents should be as follows:

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

## Check the configuration is valid

You should test your configuration is valid before you proceed.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd configtest -c /data/server.toml
```

## Default Admin Account

Then you can setup the initial admin account and initialise the database into your volume. This
command will generate a new random password for the admin account.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd recover_account -c /data/server.toml admin
# success - recover_account password for user admin: vv...
```

## Run the Server

Now we can run the server so that it can accept connections. This defaults to using
`-c /data/server.toml`

```bash
docker run -p 443:8443 -v kanidmd:/data kanidm/server:latest
```

## Using the NET\_BIND\_SERVICE capability

If you plan to run without using docker port mapping or some other reverse proxy, and your
bindaddress or ldapbindaddress port is less than `1024` you will need the `NET_BIND_SERVICE` in
docker to allow these port binds. You can add this with `--cap-add` in your docker run command.

```bash
docker run --cap-add NET_BIND_SERVICE --network [host OR macvlan OR ipvlan] \
    -v kanidmd:/data kanidm/server:latest
```
