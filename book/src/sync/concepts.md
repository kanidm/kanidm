# Synchronisation Concepts

## Introduction

In some environments Kanidm may be the first Identity Management system introduced. However many existing environments
have existing IDM systems that are well established and in use. To allow Kanidm to work with these, it is possible to
synchronise data between these IDM systems.

Currently Kanidm can consume (import) data from another IDM system. There are two major use cases for this:

- Running Kanidm in parallel with another IDM system
- Migrating from an existing IDM to Kanidm

An incoming IDM data source is bound to Kanidm by a sync account. All synchronised entries will have a reference to the
sync account that they came from defined by their `sync_parent_uuid`. While an entry is owned by a sync account we refer
to the sync account as having authority over the content of that entry.

The sync process is driven by a sync tool. This tool extracts the current state of the sync from Kanidm, requests the
set of changes (differences) from the IDM source, and then submits these changes to Kanidm. Kanidm will update and apply
these changes and commit the new sync state on success.

In the event of a conflict or data import error, Kanidm will halt and rollback the synchronisation to the last good
state. The sync tool should be reconfigured to exclude the conflicting entry or to remap it's properties to resolve the
conflict. The operation can then be retried.

This process can continue long term to allow Kanidm to operate in parallel to another IDM system. If this is for a
migration however, the sync account can be finalised. This terminates the sync account and removes the sync parent uuid
from all synchronised entries, moving authority of the entry into Kanidm.

Alternatelly, the sync account can be terminated which removes all synchronised content that was submitted.

## Creating a Sync Account

Creating a sync account requires administration permissions. By default this is available to members of the
`system_admins` group which `admin` is a memberof by default.

```bash
kanidm system sync create <sync account name>
kanidm system sync create ipasync
```

Once the sync account is created you can then generate the sync token which identifies the sync tool.

```bash
kanidm system sync generate-token <sync account name> <token label>
kanidm system sync generate-token ipasync mylabel
token: eyJhbGci...
```

> [!WARNING]
>
> The sync account token has a high level of privilege, able to create new accounts and groups. It should be treated
> carefully as a result!

If you need to revoke the token, you can do so with:

```bash
kanidm system sync destroy-token <sync account name>
kanidm system sync destroy-token ipasync
```

Destroying the token does NOT affect the state of the sync account and it's synchronised entries. Creating a new token
and providing that to the sync tool will continue the sync process.

## Operating the Sync Tool

The sync tool can now be run to replicate entries from the external IDM system into Kanidm.

You should refer to the chapter for the specific external IDM system you are using for details on the sync tool
configuration.

The sync tool runs in batches, meaning that changes from the source IDM service will be delayed to appear into Kanidm.
This is affected by how frequently you choose to run the sync tool.

If the sync tool fails, you can investigate details in the Kanidmd server output.

The sync tool can run "indefinitely" if you wish for Kanidm to always import data from the external source.

## Yielding Authority of Attributes to Kanidm

By default Kanidm assumes that authority over synchronised entries is retained by the sync tool. This means that
synchronised entries can not be written to in any capacity outside of a small number of internal Kanidm internal
attributes.

An administrator may wish to allow synchronised entries to have some attributes written by the instance locally. An
example is allowing passkeys to be created on Kanidm when the external synchronisation provider does not supply them.

In this case, the synchronisation agreement can be configured to yield its authority over these attributes to Kanidm.

To configure the attributes that Kanidm can control:

```bash
kanidm system sync set-yield-attributes <sync account name> [attr, ...]
kanidm system sync set-yield-attributes ipasync passkeys
```

This commands takes the set of attributes that should be yielded. To remove an attribute you declare the yield set with
that attribute missing.

```bash
kanidm system sync set-yield-attributes ipasync passkeys
# To remove passkeys from being Kanidm controlled.
kanidm system sync set-yield-attributes ipasync
```

## Finalising the Sync Account

If you are performing a migration from an external IDM to Kanidm, when that migration is completed you can nominate that
Kanidm now owns all of the imported data. This is achieved by finalising the sync account.

> [!WARNING]
>
> You can not undo this operation. Once you have finalised an agreement, Kanidm owns all of the synchronised data, and
> you can not resume synchronisation.

```bash
kanidm system sync finalise <sync account name>
kanidm system sync finalise ipasync
# Do you want to continue? This operation can NOT be undone. [y/N]
```

Once finalised, imported accounts can now be fully managed by Kanidm.

## Terminating the Sync Account

If you decide to cease importing accounts or need to remove all imported accounts from a sync account, you can choose to
terminate the agreement removing all data that was imported.

> [!WARNING]
>
> You can not undo this operation. Once you have terminated an agreement, Kanidm deletes all of the synchronised data,
> and you can not resume synchronisation.

```bash
kanidm system sync terminate <sync account name>
kanidm system sync terminate ipasync
# Do you want to continue? This operation can NOT be undone. [y/N]
```

Once terminated all imported data will be deleted by Kanidm.
