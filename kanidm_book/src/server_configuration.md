## Configuring the Server

### Configuring server.toml

You need a configuration file in the volume named `server.toml`. (Within the container it should be `/data/server.toml`) Its contents should be as follows:

```
{{#rustdoc_include ../../examples/server_container.toml}}
```

This example is located in [examples/server_container.toml](https://github.com/kanidm/kanidm/blob/master/examples/server_container.toml).

{{#template
    templates/kani-warning.md
    imagepath=images
    title=Warning!
    text=You MUST set the `domain` name correctly, aligned with your `origin`, else the server may refuse to start or some features (e.g. webauthn, oauth) may not work correctly!
}}

### Check the configuration is valid.

You should test your configuration is valid before you proceed.

    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd configtest -c /data/server.toml

### Default Admin Account

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd recover_account -c /data/server.toml admin

### Run the Server

Now we can run the server so that it can accept connections. This defaults to using `-c /data/server.toml`

    docker run -p 8443:8443 -v kanidmd:/data kanidm/server:latest

