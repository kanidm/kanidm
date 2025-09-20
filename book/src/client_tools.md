# Client Tools

To interact with Kanidm as an administrator, you'll need to use our command line tools. If you haven't installed them
yet, [install them now](installing_client_tools.md).

## Kanidm configuration

You can configure `kanidm` to help make commands simpler by modifying `~/.config/kanidm` or `/etc/kanidm/config`.

```toml
uri = "https://idm.example.com"
ca_path = "/path/to/ca.pem"
```

The full configuration reference is in the
[definition of `KanidmClientConfig`](https://kanidm.github.io/kanidm/master/rustdoc/kanidm_client/struct.KanidmClientConfig.html).

Once configured, you can test this with:

```bash
kanidm self whoami --name anonymous
```

## Session Management

To authenticate as a user (for use with the command line), you need to use the `login` command to establish a session
token.

```bash
kanidm login --name USERNAME
kanidm login --name admin
kanidm login -D USERNAME
kanidm login -D admin
```

Once complete, you can use `kanidm` without re-authenticating for a period of time for administration.

You can list active sessions with:

```bash
kanidm session list
```

Sessions will expire after a period of time. To remove these expired sessions locally you can use:

```bash
kanidm session cleanup
```

To log out of a session:

```bash
kanidm logout --name USERNAME
kanidm logout --name admin
```

## Multiple Instances

In some cases you may have multiple Kanidm instances. For example you may have a production instance and a development
instance. This can introduce friction for admins when they need to change between those instances.

The Kanidm cli tool allows you to configure multiple instances and swap between them with an environment variable, or
the `--instance` flag. Instances maintain separate session stores.

```toml
uri = "https://idm.example.com"
ca_path = "/path/to/ca.pem"

["development"]
uri = "https://idm.dev.example.com"
ca_path = "/path/to/dev-ca.pem"
```

The instance can then be selected with:

```
export KANIDM_INSTANCE=development
kanidm login -D username@idm.dev.example.com
```

To return to the default instance you `unset` the `KANIDM_INSTANCE` variable.
