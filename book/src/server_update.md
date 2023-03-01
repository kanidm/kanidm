# Updating the Server

Docker doesn't follow a "traditional" method of updates. Rather you remove the old version of the
container and recreate it with a newer version. This document will help walk you through that
process.

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-alert.md
imagepath=images
title=Tip
text=You should have documented and preserved your kanidm container create / run command from the server preparation guide. If not, you'll need to use "docker inspect" to work out how to recreate these parameters.
}}

<!-- deno-fmt-ignore-end -->

## Preserving the Previous Image

You may wish to preserve the previous image before updating. This is useful if an issue is
encountered in upgrades.

```bash
docker tag kanidm/server:latest kanidm/server:<DATE>
docker tag kanidm/server:latest kanidm/server:2022-10-24
```

## Update your Image

Pull the latest version of Kanidm.

```bash
docker pull kanidm/server:latest
docker pull kanidm/radius:latest
docker pull kanidm/tools:latest
```

## Perform a backup

See [backup and restore](backup_restore.md)

## Update your Instance

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=WARNING
text=Downgrades are not possible. It is critical you know how to backup and restore before you proceed with this step.
}}

<!-- deno-fmt-ignore-end -->

Docker updates by deleting and recreating the instance. All that needs to be preserved is contained
in your storage volume.

```bash
docker stop <previous instance name>
```

You can test that your configuration is correct, and the server should correctly start.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd configtest -c /data/server.toml
```

You can then follow through with the upgrade by running the create / run command with your existing
volume.

```bash
docker run [Your Arguments Here] -v kanidmd:/data \
    OTHER_CUSTOM_OPTIONS \
    kanidm/server:latest
```

Once you confirm the upgrade is successful you can delete the previous instance

```bash
docker rm <previous instance name>
```

If you encounter an issue you can revert to the previous version.

```bash
docker stop <new instance name>
docker start <previous instance name>
```

If you deleted the previous instance, you can recreate it from your preserved tag instead.

```bash
docker run -p ports -v volumes kanidm/server:<DATE>
```

If the server from your previous version fails to start, you will need to restore from backup.
