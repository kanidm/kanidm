# Administration Tasks

This chapter describes some of the routine administration tasks for running
a Kanidm server, such as making backups and restoring from backups, testing
server configuration, reindexing, verifying data consistency, and renaming
your domain.

# Backup and Restore

With any Identity Management (IDM) software, it's important you have the capability to restore in 
case of a disaster - be that physical damage or a mistake. Kanidm supports backup 
and restore of the database with three methods.

## Method 1 (Preferred)

Method 1 involves taking a backup of the database entry content, which is then re-indexed on restore.
This is the preferred method.

To take the backup (assuming our docker environment) you first need to stop the instance:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
        kanidm/server:latest /sbin/kanidmd backup -c /data/server.toml \
        /backup/kanidm.backup.json
    docker start <container name>

You can then restart your instance. DO NOT modify the backup.json as it may introduce
data errors into your instance.

To restore from the backup:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
        kanidm/server:latest /sbin/kanidmd restore -c /data/server.toml \
        /backup/kanidm.backup.json
    docker start <container name>

That's it!

## Method 2

This is a simple backup of the data volume.

    docker stop <container name>
    # Backup your docker's volume folder
    docker start <container name>

## Method 3

Automatic backups can be generated online by a `kanidmd server` instance
by including the `[online_backup]` section in the `server.toml`.
This allows you to run regular backups, defined by a cron schedule, and maintain
the number of backup versions to keep. An example is located in 
[examples/server.toml](https://github.com/kanidm/kanidm/blob/master/examples/server.toml).

# Configuration Test

You can test your configuration will correctly start with the server.

> **WARNING:** While this is a configuration test, it still needs to open the database so that
> it can check a number of internal values are consistent with the configuration. As a result,
> this requires the instance under config test to be stopped!

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd configtest -c /data/server.toml
    docker start <container name>


# Reindexing after schema extension

In some (rare) cases you may need to reindex.
Please note the server will sometimes reindex on startup as a result of the project
changing its internal schema definitions. This is normal and expected - you may never need
to start a reindex yourself as a result!

You'll likely notice a need to reindex if you add indexes to schema and you see a message in 
your logs such as:

    Index EQUALITY name not found
    Index {type} {attribute} not found

This indicates that an index of type equality has been added for name, but the indexing process
has not been run. The server will continue to operate and the query execution code will correctly
process the query - however it will not be the optimal method of delivering the results as we need to
disregard this part of the query and act as though it's un-indexed.

Reindexing will resolve this by forcing all indexes to be recreated based on their schema
definitions (this works even though the schema is in the same database!)

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd reindex -c /data/server.toml
    docker start <container name>

Generally, reindexing is a rare action and should not normally be required.

# Vacuum

[Vacuuming](https://www.sqlite.org/lang_vacuum.html) is the process of reclaiming un-used pages
from the sqlite freelists, as well as performing some data reordering tasks that may make some
queries more efficient . It is recommended that you vacuum after a reindex is performed or
when you wish to reclaim space in the database file.

Vacuum is also able to change the pagesize of the database. After changing `db_fs_type` (which affects
pagesize) in server.toml, you must run a vacuum for this to take effect:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd vacuum -c /data/server.toml
    docker start <container name>

# Verification

The server ships with a number of verification utilities to ensure that data is consistent such
as referential integrity or memberof.

Note that verification really is a last resort - the server does _a lot_ to prevent and self-heal
from errors at run time, so you should rarely if ever require this utility. This utility was
developed to guarantee consistency during development!

You can run a verification with:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd verify -c /data/server.toml
    docker start <container name>

If you have errors, please contact the project to help support you to resolve these.

# Rename the domain

There are some cases where you may need to rename the domain. You should have configured
this initially in the setup, however you may have a situation where a business is changing
name, merging, or other needs which may prompt this needing to be changed.

> **WARNING:** This WILL break ALL u2f/webauthn tokens that have been enrolled, which MAY cause
> accounts to be locked out and unrecoverable until further action is taken. DO NOT CHANGE
> the domain name unless REQUIRED and have a plan on how to manage these issues.

> **WARNING:** This operation can take an extensive amount of time as ALL accounts and groups
> in the domain MUST have their Security Principal Names (SPNs) regenerated. This WILL also cause 
> a large delay in replication once the system is restarted.

You should make a backup before proceeding with this operation.

When you have a created a migration plan and strategy on handling the invalidation of webauthn,
you can then rename the domain.

First, stop the instance.

    docker stop <container name>

Second, change `domain` and `origin` in `server.toml`.

Third, trigger the database domain rename process.

    docker run --rm -i -t -v kanidmd:/data \
        kanidm/server:latest /sbin/kanidmd domain_name_change -c /data/server.toml

Finally, you can now start your instance again.

    docker start <container name>

# Raw actions

The server has a low-level stateful API you can use for more complex or advanced tasks on large numbers
of entries at once. Some examples are below, but generally we advise you to use the APIs as listed
above.

    # Create from json (group or account)
    kanidm raw create -H https://localhost:8443 -C ../insecure/ca.pem -D admin example.create.account.json
    kanidm raw create  -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin example.create.group.json

    # Apply a json stateful modification to all entries matching a filter
    kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"or": [ {"eq": ["name", "idm_person_account_create_priv"]}, {"eq": ["name", "idm_service_account_create_priv"]}, {"eq": ["name", "idm_account_write_priv"]}, {"eq": ["name", "idm_group_write_priv"]}, {"eq": ["name", "idm_people_write_priv"]}, {"eq": ["name", "idm_group_create_priv"]} ]}' example.modify.idm_admin.json
    kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"eq": ["name", "idm_admins"]}' example.modify.idm_admin.json

    # Search and show the database representations
    kanidm raw search -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"eq": ["name", "idm_admin"]}'

    # Delete all entries matching a filter
    kanidm raw delete -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"eq": ["name", "test_account_delete_me"]}'
