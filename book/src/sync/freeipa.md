# FreeIPA

FreeIPA is a popular opensource LDAP and Kerberos provider, aiming to be "Active Directory" for Linux.

Kanidm is able to synchronise from FreeIPA for the purposes of coexistence or migration.

## Installing the FreeIPA Sync Tool

See [installing the client tools](../installing_client_tools.md). The ipa sync tool is part of the
[tools container](../installing_client_tools.md#tools-container).

## Configure the FreeIPA Sync Tool

The sync tool is a bridge between FreeIPA and Kanidm, meaning that the tool must be configured to communicate to both
sides.

Like other components of Kanidm, the FreeIPA sync tool will read your /etc/kanidm/config if present to understand how to
connect to Kanidm.

The sync tool specific components are configured in its own configuration file.

```toml
{{#rustdoc_include ../../../examples/kanidm-ipa-sync}}
```

This example is located in
[examples/kanidm-ipa-sync](https://github.com/kanidm/kanidm/blob/master/examples/kanidm-ipa-sync).

In addition to this, you must make some configuration changes to FreeIPA to enable synchronisation.

You can find the name of your 389 Directory Server instance with:

```bash
# Run on the FreeIPA server
dsctl --list
> slapd-DEV-KANIDM-COM
```

Using this you can show the current status of the retro changelog plugin to see if you need to change it's
configuration.

```bash
# Run on the FreeIPA server
dsconf <instance name> plugin retro-changelog show
dsconf slapd-DEV-KANIDM-COM plugin retro-changelog show
```

You must modify the retro changelog plugin to include the full scope of the database suffix so that the sync tool can
view the changes to the database. Currently dsconf can not modify the include-suffix so you must do this manually.

You need to change the `nsslapd-include-suffix` to match your FreeIPA baseDN here. You can access the basedn with:

```bash
ldapsearch -H ldaps://<IPA SERVER HOSTNAME/IP> -x -b '' -s base namingContexts
# namingContexts: dc=ipa,dc=dev,dc=kanidm,dc=com
```

You should ignore `cn=changelog` and `o=ipaca` as these are system internal namingContexts. You can then create an
ldapmodify like the following.

```rust
{{#rustdoc_include ../../../tools/iam_migrations/freeipa/00config-mod.ldif}}
```

And apply it with:

```bash
ldapmodify -f change.ldif -H ldaps://<IPA SERVER HOSTNAME/IP> -x -D 'cn=Directory Manager' -W
# Enter LDAP Password:
```

You must then reboot your FreeIPA server.

## Running the Sync Tool Manually

You can perform a dry run with the sync tool manually to check your configurations are correct and that the tool can
synchronise from FreeIPA.

```bash
kanidm-ipa-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ipa-sync -n
kanidm-ipa-sync -i /etc/kanidm/ipa-sync -n
```

As the sync tool is part of the tools container, you can run this with:

```bash
docker run --rm -i -t \
  --user uid:gid \
  -p 12345:12345 \
  -v /etc/kanidm/config:/etc/kanidm/config:ro \
  -v /path/to/kanidm.ca.pem:/path/to/kanidm.ca.pem:ro
  -v /path/to/ipa-ca.pem:/etc/kanidm/ipa-ca.pem:ro \
  -v /path/to/ipa-sync:/etc/kanidm/ipa-sync:ro \
  kanidm/tools:latest \
  kanidm-ipa-sync -i /etc/kanidm/ipa-sync -
```

## Running the Sync Tool Automatically

The sync tool can be run on a schedule if you configure the `schedule` parameter, and provide the option "--schedule" on
the cli

```bash
kanidm-ipa-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ipa-sync --schedule
kanidm-ipa-sync -i /etc/kanidm/ipa-sync --schedule
```

As the sync tool is part of the tools container, you can run this with:

```bash
docker run --name kanidm-ipa-sync \
  --user uid:gid \
  -p 12345:12345 \
  -v /etc/kanidm/config:/etc/kanidm/config:ro \
  -v /path/to/kanidm.ca.pem:/path/to/kanidm.ca.pem:ro
  -v /path/to/ipa-ca.pem:/etc/kanidm/ipa-ca.pem:ro \
  -v /path/to/ipa-sync:/etc/kanidm/ipa-sync:ro \
  kanidm/tools:latest \
  kanidm-ipa-sync -i /etc/kanidm/ipa-sync --schedule
```

## Monitoring the Sync Tool

When running in schedule mode, you may wish to monitor the sync tool for failures. Since failures block the sync
process, this is important to ensuring a smooth and reliable synchronisation process.

You can configure a status listener that can be monitored via tcp with the parameter `status_bind`.

An example of monitoring this with netcat is:

```bash
# status_bind = "[::1]:12345"
# nc ::1 12345
Ok
```

It's important to note no details are revealed via the status socket, and is purely for Ok or Err status of the last
sync. This status socket is suitable for monitoring from tools such as Nagios.
