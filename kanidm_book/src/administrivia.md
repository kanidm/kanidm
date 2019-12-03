# Administration Tasks

There are a number of tasks that you may wish to perform as an administrator of a service like kanidm.

# Backup and Restore

With any idm software, it's important you have the capability to restore in case of a disaster - be
that physical damage or mistake. Kanidm supports backup and restore of the database with two methods.

## Method 1

Method 1 involves taking a backup of the database entry content, which is then re-indexed on restore.
This is the "prefered" method.

To take the backup (assuming our docker environment) you first need to stop the instance:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
        firstyear/kanidmd:latest /sbin/kanidmd backup \
        /backup/kanidm.backup.json -D /data/kanidm.db
    docker start <container name>

You can then restart your instance. It's advised you DO NOT modify the backup.json as it may introduce
data errors into your instance.

To restore from the backup:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data -v kanidmd_backups:/backup \
        firstyear/kanidmd:latest /sbin/kanidmd restore \
        /backup/kanidm.backup.json -D /data/kanidm.db
    docker start <container name>

That's it!

## Method 2

This is a simple backup of the data volume.

    docker stop <container name>
    # Backup your docker's volume folder
    docker start <container name>

# Rename the domain

There are some cases where you may need to rename the domain. You should have configured
this initially in the setup, however you may have a situation where a business is changing
name, merging, or other needs which may prompt this needing to be changed.

WARNING: This WILL break ALL u2f/webauthn tokens that have been enrolled, which MAY cause
accounts to be locked out and unrecoverable until further action is taken. DO NOT CHANGE
the domain_name unless REQUIRED and have a plan on how to manage these issues.

WARNING: This operation can take an extensive amount of time as ALL accounts and groups
in the domain MUST have their SPN's regenerated. This will also cause a large delay in
replication once the system is restarted.

You should take a backup before proceeding with this operation.

When you have a created a migration plan and strategy on handling the invalidation of webauthn,
you can then rename the domain with the commands as follows:

    docker stop <container name>
    docker run --rm -i -t -v kandimd:/data \
        firstyear/kanidm:latest /sbin/kanidmd domain_name_change \
        -D /data/kanidm.db -n idm.new.domain.name
    docker start <container name>


# Reindexing after schema extension

In some (rare) cases you may need to reindex.
Please note the server will sometimes reindex on startup as a result of the project
changing it's internal schema definitions. This is normal and expected - you may never need
to start a reindex yourself as a result!

You'll likely notice a need to reindex if you add indexes to schema and you see a message in your logs such as:

    Index EQUALITY name not found
    Index {type} {attribute} not found

This indicates that an index of type equality has been added for name, but the indexing process
has not been run - the server will continue to operate and the query execution code will correctly
process the query however it will not be the optimal method of delivering the results as we need to
disregard this part of the query and act as though it's un-indexed.

Reindexing will resolve this by forcing all indexes to be recreated based on their schema
definitions (this works even though the schema is in the same database!)

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        firstyear/kanidmd:latest /sbin/kanidmd reindex \
        -D /data/kanidm.db
    docker start <container name>

Generally reindexing is a rare action and should not normally be required.

# Verification

The server ships with a number of verification utilities to ensure that data is consistent such
as referential integrity or memberof.

Note that verification really is a last resort - the server does *a lot* to prevent and self-heal
from errors at run time, so you should rarely if ever require this utility. This utility was
developed to guarantee consistency during development!

You can run a verification with:

    docker stop <container name>
    docker run --rm -i -t -v kanidmd:/data \
        firstyear/kanidmd:latest /sbin/kanidmd verify \
        -D /data/kanidm.db
    docker start <container name>

If you have errors, please contact the project to help support you to resolve these.

# Raw actions

The server has a low-level stateful API you can use for more complex or advanced tasks on large numbers
of entries at once. Some examples are below, but generally we advise you to use the apis as listed
above.

    # Create from json (group or account)
    kanidm raw create -H https://localhost:8443 -C ../insecure/ca.pem -D admin example.create.account.json
    kanidm raw create  -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin example.create.group.json

    # Apply a json stateful modification to all entries matching a filter
    kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"Or": [ {"Eq": ["name", "idm_person_account_create_priv"]}, {"Eq": ["name", "idm_service_account_create_priv"]}, {"Eq": ["name", "idm_account_write_priv"]}, {"Eq": ["name", "idm_group_write_priv"]}, {"Eq": ["name", "idm_people_write_priv"]}, {"Eq": ["name", "idm_group_create_priv"]} ]}' example.modify.idm_admin.json
    kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"Eq": ["name", "idm_admins"]}' example.modify.idm_admin.json

    # Search and show the database representations
    kanidm raw search -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"Eq": ["name", "idm_admin"]}'
    > Entry { attrs: {"class": ["account", "memberof", "object"], "displayname": ["IDM Admin"], "memberof": ["idm_people_read_priv", "idm_people_write_priv", "idm_group_write_priv", "idm_account_read_priv", "idm_account_write_priv", "idm_service_account_create_priv", "idm_person_account_create_priv", "idm_high_privilege"], "name": ["idm_admin"], "uuid": ["bb852c38-8920-4932-a551-678253cae6ff"]} }

    # Delete all entries matching a filter
    kanidm raw delete -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"Eq": ["name", "test_account_delete_me"]}'
