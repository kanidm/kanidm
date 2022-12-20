# Synchronising from FreeIPA

FreeIPA is a popular opensource LDAP and Kerberos provider, aiming to be "Active Directory" for
Linux.

Kanidm is able to synchronise from FreeIPA for the purposes of coexistence or migration.

## Installing the FreeIPA Sync Tool

See [installing the client tools](../installing_client_tools.md).

## Configure the FreeIPA Sync Tool

The sync tool is a bridge between FreeIPA and Kanidm, meaning that the tool must be configured to
communicate to both sides.

Like other components of Kanidm, the FreeIPA sync tool will read your /etc/kanidm/config if present
to understand how to connect to Kanidm.

The sync tool specific components are configured in it's own configuration file.

```
{{#rustdoc_include ../../../examples/kanidm-ipa-sync}}
```

This example is located in [examples/kanidm-ipa-sync](https://github.com/kanidm/kanidm/blob/master/examples/kanidm-ipa-sync).

In addition to this, you must make some configuration changes to FreeIPA to enable synchronisation.

You must modify the retro changelog plugin to include the full scope of the database suffix.

```
{{#rustdoc_include ../../../iam_migrations/freeipa/00config-mod.ldif}}
```

You must then restart your FreeIPA server.

## Running the Sync Tool Manually

You can perform a dry run with the sync tool manually to check your configurations are
correct.

    kanidm-ipa-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ipa-sync -n
    kanidm-ipa-sync -i /etc/kanidm/ipa-sync -n

## Running the Sync Tool Automatically

The sync tool can be run on a schedule if you configure the `schedule` parameter, and provide
the option "--schedule" on the cli

    kanidm-ipa-sync [-c /path/to/kanidm/config] -i /path/to/kanidm-ipa-sync --schedule

## Monitoring the Sync Tool

When running in schedule mode, you may wish to monitor the sync tool for failures. Since failures
block the sync process, this is important to ensuring a smooth and reliable synchronisation process.

You can configure a status listener that can be monitored via tcp with the parameter `status_bind`.

An example of monitoring this with netcat is:

    # status_bind = "[::1]:12345"
    # nc ::1 12345
    Ok

It's important to note no details are revealed via the status socket, and is purely for Ok or Err status
of the last sync.

