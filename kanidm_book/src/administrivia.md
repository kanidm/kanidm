# Administration Tasks

This chapter describes some of the routine administration tasks for running
a Kanidm server, such as making backups and restoring from backups, testing
server configuration, reindexing, verifying data consistency, and renaming
your domain.

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
        kanidm/server:latest /sbin/kanidmd domain rename -c /data/server.toml

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
