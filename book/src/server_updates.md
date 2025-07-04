# Server Updates

## General Update Notes

During some upgrades the Kanidm project must apply new constraints or limits on your data. If we are unable to migrate
these without disruption, we rely on administrators to make informed choices before the upgrade can proceed.

When these are required, we will give you one release cycle ahead of time to make changes. To check for changes that
will affect your instance you should run.

```bash
kanidmd domain upgrade-check

# Running domain upgrade check ...
# domain_name            : localhost
# domain_uuid            : 7dcc7a71-b488-4e2c-ad4d-d89fc49678cb
# ------------------------
# upgrade_item           : gidnumber range validity
# status                 : PASS
```

If _any_ task yields a `FAIL` then a future upgrade will also fail. A `FAIL` status will provide you a list of actions
and affected entries that must be resolved before the next upgrade can complete successfully. If all tasks yield a
`PASS` status then you can begin the upgrade process.

## Docker Update Procedure

Docker doesn't follow a "traditional" method of updates. Rather you remove the old version of the container and recreate
it with a newer version. This document will help walk you through that process.

> [!TIP]
>
> You should have documented and preserved your Kanidm container create / run command from the server preparation guide.
> If not, you'll need to use `docker inspect` to work out how to recreate these parameters.

### Upgrade Check

Perform the pre-upgrade check.

```bash
docker exec -i -t <container name> \
  kanidmd domain upgrade-check

# Running domain upgrade check ...
# domain_name            : localhost
# domain_uuid            : 7dcc7a71-b488-4e2c-ad4d-d89fc49678cb
# ------------------------
# upgrade_item           : gidnumber range validity
# status                 : PASS
```

### Preserving the Previous Image

You may wish to preserve the previous image before updating. This is useful if an issue is encountered in upgrades.

```bash
docker tag kanidm/server:latest kanidm/server:<DATE>
docker tag kanidm/server:latest kanidm/server:2022-10-24
```

### Update your Image

Pull the latest version of Kanidm.

```bash
docker pull kanidm/server:latest
docker pull kanidm/radius:latest
docker pull kanidm/tools:latest
```

### Perform a backup

See [backup and restore](backup_and_restore.md)

### Update your Instance

> [!WARNING]
>
> Downgrades are not possible. It is critical you know how to backup and restore before you proceed with this step.

Docker updates operate by deleting and recreating the container. All state that needs to be preserved is within your
storage volume.

```bash
docker stop <previous instance name>
```

You can test that your configuration is correct with the new version, and the server should correctly start.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd configtest
```

You can then follow through with the upgrade by running the create / run command with your existing volume.

```bash
docker run [Your Arguments Here] -v kanidmd:/data \
    OTHER_CUSTOM_OPTIONS \
    kanidm/server:latest
```

Once you confirm the upgrade is successful you can delete the previous instance

```bash
docker rm <previous instance name>
```

If you encounter an issue you can revert to the previous version. Upgrades are performed in a single transaction and no
changes to your data are made unless the upgrade was successful.

```bash
docker stop <new instance name>
docker start <previous instance name>
```

If you deleted the previous instance, you can recreate it from your preserved tag instead.

```bash
docker run [Your Arguments Here] -v kanidmd:/data \
    OTHER_CUSTOM_OPTIONS \
    kanidm/server:<DATE>
```

In rare and exceptional cases, if the server from your previous version fails to start, you will need to restore from
backup.
