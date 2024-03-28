# Backup and Restore

With any Identity Management (IDM) software, it's important you have the capability to restore in
case of a disaster - be that physical damage or a mistake. Kanidm supports backup and restore of the
database with three methods.

## Method 1 - Automatic Backup

Automatic backups can be generated online by a `kanidmd server` instance by including the
`[online_backup]` section in the `server.toml`. This allows you to run regular backups, defined by a
cron schedule, and maintain the number of backup versions to keep. An example is located in
[examples/server.toml](https://github.com/kanidm/kanidm/blob/master/examples/server.toml).

## Method 2 - Manual Backup

This method uses the same process as the automatic process, but is manually invoked. This can be
useful for pre-upgrade backups

To take the backup (assuming our docker environment) you first need to stop the instance:

```bash
docker stop <container name>
docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
    kanidm/server:latest /sbin/kanidmd database backup -c /data/server.toml \
    /backup/kanidm.backup.json
docker start <container name>
```

You can then restart your instance. DO NOT modify the backup.json as it may introduce data errors
into your instance.

To restore from the backup:

```bash
docker stop <container name>
docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
    kanidm/server:latest /sbin/kanidmd database restore -c /data/server.toml \
    /backup/kanidm.backup.json
docker start <container name>
```

## Method 3 - Manual Database Copy

This is a simple backup of the data volume containing the database files. Ensure you copy the whole
folder, rather than individual files in the volume!

```bash
docker stop <container name>
# Backup your docker's volume folder
# cp -a /path/to/my/volume /path/to/my/backup-volume
docker start <container name>
```

Restoration is the reverse process where you copy the entire folder back into place.
