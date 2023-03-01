# Client tools

To interact with Kanidm as an administrator, you'll need to use our command line tools. If you
haven't installed them yet, [install them now](installing_client_tools.md).

## Kanidm configuration

You can configure `kanidm` to help make commands simpler by modifying `~/.config/kanidm` or
`/etc/kanidm/config`.

```toml
uri = "https://idm.example.com"
verify_ca = true|false
verify_hostnames = true|false
ca_path = "/path/to/ca.pem"
```

Once configured, you can test this with:

```bash
kanidm self whoami --name anonymous
```

## Session Management

To authenticate as a user (for use with the command line), you need to use the `login` command to
establish a session token.

```bash
kanidm login --name USERNAME
kanidm login --name admin
```

Once complete, you can use `kanidm` without re-authenticating for a period of time for
administration.

You can list active sessions with:

```bash
kanidm session list
```

Sessions will expire after a period of time (by default 1 hour). To remove these expired sessions
locally you can use:

```bash
kanidm session cleanup
```

To log out of a session:

```bash
kanidm logout --name USERNAME
kanidm logout --name admin
```
