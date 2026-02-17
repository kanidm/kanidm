# Entry Management

Kanidm supports a SCIM based entry management/migration process. This process allows configuration management tools such
Ansible or Salt to deploy HJSON formatted person and group records that can be imported to the server. HJSON is JSON
that allows commenting.

## Migration Path

Migrations are stored in the path defined by `server.toml`:`migration_path`. The default for containers is
`/data/migrations.d`.

Files within the folder must match the pattern `xx-name.json` / `xx-name.hjson` where `xx` are numeric digits. For
example the following are valid names:

- `00-base.json`
- `99-user.json`
- `80-group-defines.json`
- `99-accounts.hjson`

The following are invalid:

- `data.json` - missing preceeding numbers and hyphen.
- `00base.json` - missing `-` between numbers and name.
- `00-base.scim` - incorrect file extension.

## Record Syntax

Entries can be asserted to be present, and in a specific attribute state. Or they can be absent from the database.
Attributes of an entry can be removed by setting them to `null`.

```json
{{#rustdoc_include ../../examples/migrations/00-basic.hjson}}
```

This example is located in [examples/migrations](https://github.com/kanidm/kanidm/blob/master/examples/migrations/) in
the repository. There are other migrations there you may find useful.

## Recommendations

Migrations should only be deployed to a single node in your Kanidm topology. Replication will ensure that all nodes have
a consistent state. This prevents races or flip-flop conditions that could otherwise occur.

## Application Details

There are some important details for how Kanidm applies these migrations. This is due to the fact that Kanidm is a
distributed system, and we strive to ensure that all data is consistent and correct.

### Filesystem Access

Since these migrations are on the filesystem of the Kanidm server, this implies that access to the machine (and
subsequently this folder) has a high level of access. As a result, these migrations can perform almost all actions that
you would expect of the `idm_admin` or `admin` account.

### Valid Attributes

Not all attributes may be asserted via migrations. Examples include password hashes, OAuth2 basic secrets, and other
credentials. Only a subset of values may be asserted on entries.

### Only Once

When you apply a migration, the content of the file is hashed and saved with the ID of the applied migration. If the
file content _has not changed_ as verified by the hash, then the migration is NOT re-applied. This is to try to limit
the "churn" on the database, but also to prevent migrations from removing user-applied changes once they are applied.

If the migration is changed, then it will be re-applied exactly once.

### Timing

Migrations are applied during server startup, and when the server is reloaded (via the reload command, or SIGHUP).

### Assertion Application Order

Migrations are applied in lexical order. This allows you to assert dependencies between migrations that may exist.

Assertions in migrations are applied in batches depending on the needed state that must be arrived at. For example if
your assertion contained:

```
- user that exists
- group that must be created
- group that exists
```

Then the migration will apply these three operations in sequential order. However, once complete, all three changes
would be applied in a single batch to assert entry state. This has consequences for groups and group memberships.

For example if you had:

```
- group with member X which does exist
- user X that does not exist
```

Since these would be split, the change to the group would fail since user X does not yet exist. However were both
entries to be initially absent, they would be created together and the operation would succeed.

For this reason, it's advised that you maintain separate migrations for accounts and groups, to assert that the correct
ordering is applied during operation.

This is why migrations are applied in lexical order.
