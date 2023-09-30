# Synchronising from FreeIPA

If you have an LDAP server that supports sync repl (rfc4533 content synchronisation) then you are
able to synchronise from it to Kanidm for the purposes of coexistence or migration.

If there is a specific Kanidm sync tool for your LDAP server, you should use that instead of the
generic LDAP server sync.

## Installing the LDAP Sync Tool

See [installing the client tools](../installing_client_tools.md).

## Configure the LDAP Sync Tool

The sync tool is a bridge between LDAP and Kanidm, meaning that the tool must be configured to
communicate to both sides.

Like other components of Kanidm, the LDAP sync tool will read your /etc/kanidm/config if present to
understand how to connect to Kanidm.

The sync tool specific components are configured in it's own configuration file.

```toml
{{#rustdoc_include ../../../examples/kanidm-ldap-sync}}
```

This example is located in
[examples/kanidm-ldap-sync](https://github.com/kanidm/kanidm/blob/master/examples/kanidm-ldap-sync).

In addition to this, you may be required to make some configuration changes to your LDAP server to
enable synchronisation.

### OpenLDAP

You must enable the syncprov overlay in slapd.conf

```
moduleload syncprov.la
overlay syncprov
```

In addition you must grant an account full read access and raise its search limits.

```
access to *
    by dn.base="cn=sync,dc=example,dc=com" read
    by * break

limits dn.exact="cn=sync,dc=example,dc=com" time.soft=unlimited time.hard=unlimited size.soft=unlimited size.hard=unlimited
```

For more details see the
[openldap administration guide](https://openldap.org/doc/admin24/replication.html#Configuring%20the%20different%20replication%20types).

### 389 Directory Server

You can find the name of your 389 Directory Server instance with:

```bash
dsconf --list
```

Using this you can show the current status of the retro changelog plugin to see if you need to
change its configuration.

```bash
dsconf <instance name> plugin retro-changelog show
dsconf slapd-DEV-KANIDM-COM plugin retro-changelog show
```

You must modify the retro changelog plugin to include the full scope of the database suffix so that
the sync tool can view the changes to the database. Currently dsconf can not modify the
include-suffix so you must do this manually.

You need to change the `nsslapd-include-suffix` to match your FreeIPA baseDN here. You can access
the basedn with:

```bash
ldapsearch -H ldaps://<SERVER HOSTNAME/IP> -x -b '' -s base namingContexts
# namingContexts: dc=ldap,dc=dev,dc=kanidm,dc=com
```

You should ignore `cn=changelog` as this is a system internal namingContext. You can then create an
ldapmodify like the following.

```rust
{{#rustdoc_include ../../../tools/iam_migrations/freeipa/00config-mod.ldif}}
```

And apply it with:

```bash
ldapmodify -f change.ldif -H ldaps://<SERVER HOSTNAME/IP> -x -D 'cn=Directory Manager' -W
# Enter LDAP Password:
```

You must then reboot your 389 Directory Server.

## Running the Sync Tool Manually

You can perform a dry run with the sync tool manually to check your configurations are correct and
that the tool can synchronise from FreeIPA.

```bash
kanidm-ldap-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ldap-sync -n
kanidm-ldap-sync -i /etc/kanidm/ldap-sync -n
```

## Running the Sync Tool Automatically

The sync tool can be run on a schedule if you configure the `schedule` parameter, and provide the
option "--schedule" on the cli

```bash
kanidm-ldap-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ldap-sync --schedule
kanidm-ldap-sync -i /etc/kanidm/ldap-sync --schedule
```

As the sync tool is part of the tools container, you can run this with:

```bash
docker create --name kanidm-ldap-sync \
  --user uid:gid \
  -p 12345:12345 \
  -v /etc/kanidm/config:/etc/kanidm/config:ro \
  -v /path/to/ldap-sync:/etc/kanidm/ldap-sync:ro \
  kanidm-ipa-sync -i /etc/kanidm/ldap-sync --schedule
```

## Monitoring the Sync Tool

When running in schedule mode, you may wish to monitor the sync tool for failures. Since failures
block the sync process, this is important for a smooth and reliable synchronisation process.

You can configure a status listener that can be monitored via tcp with the parameter `status_bind`.

An example of monitoring this with netcat is:

```bash
# status_bind = "[::1]:12345"
# nc ::1 12345
Ok
```

It's important to note no details are revealed via the status socket, and is purely for Ok or Err
status of the last sync. This status socket is suitable for monitoring from tools such as Nagios.
