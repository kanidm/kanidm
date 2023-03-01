# Rename the domain

There are some cases where you may need to rename the domain. You should have configured this
initially in the setup, however you may have a situation where a business is changing name, merging,
or other needs which may prompt this needing to be changed.

> **WARNING:** This WILL break ALL u2f/webauthn tokens that have been enrolled, which MAY cause
> accounts to be locked out and unrecoverable until further action is taken. DO NOT CHANGE the
> domain name unless REQUIRED and have a plan on how to manage these issues.

> **WARNING:** This operation can take an extensive amount of time as ALL accounts and groups in the
> domain MUST have their Security Principal Names (SPNs) regenerated. This WILL also cause a large
> delay in replication once the system is restarted.

You should make a backup before proceeding with this operation.

When you have a created a migration plan and strategy on handling the invalidation of webauthn, you
can then rename the domain.

First, stop the instance.

```bash
docker stop <container name>
```

Second, change `domain` and `origin` in `server.toml`.

Third, trigger the database domain rename process.

```bash
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd domain rename -c /data/server.toml
```

Finally, you can now start your instance again.

```bash
docker start <container name>
```
