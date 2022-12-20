# Synchronisation Concepts

## Introduction

In some environments Kanidm may be the first Identity Management system introduced. However many
existing environments have existing IDM systems that are well established and in use. To allow
Kanidm to work with these, it is possible to synchronised data between these IDM systems.

Currently Kanidm can consume (import) data from another IDM system. There are two major use cases
for this:

* Running Kanidm in parallel with another IDM system
* Migrating from an existing IDM to Kanidm

An incoming IDM data source is bound to Kanidm by a sync account. All synchronised entries will
have a reference to the sync account that they came from defined by their "sync parent uuid".
While an entry is owned by a sync account we refer to the sync account as having authority over
the content of that entry.

The sync process is driven by a sync tool. This tool extracts the current state of the sync from
Kanidm, requests the set of changes (differences) from the IDM source, and then submits these
changes to Kanidm. Kanidm will update and apply these changes and commit the new sync state on
success.

In the event of a conflict or data import error, Kanidm will halt and rollback the synchronisation
to the last good state. The sync tool should be reconfigured to exclude the conflicting entry or
to remap it's properties to resolve the conflict. The operation can then be retried.

This process can continue long term to allow Kanidm to operate in parallel to another IDM system. If
this is for a migration however, the sync account can be finalised. This terminates the sync account
and removes the sync parent uuid from all synchronised entries, moving authority of the entry into
Kanidm.

Alternatelly, the sync account can be terminated which removes all synchronised content that was submitted.

## Creating a Sync Account

Creating a sync account requires administration permissions. By default this is available to
members of the "system\_admins" group which "admin" is a memberof by default.

    kanidm system sync create <sync account name>
    kanidm system sync create ipasync

Once the sync account is created you can then generate the sync token which identifies the
sync tool.

    kanidm system sync generate-token <sync account name> <token label>
    kanidm system sync generate-token ipasync mylabel
    token: eyJhbGci...

{{#template  
    ../templates/kani-warning.md
    imagepath=../images
    title=Warning!
    text=The sync account token has a high level of privilege, able to create new accounts and groups. It should be treated carefully as a result!
}}

If you need to revoke the token, you can do so with:

    kanidm system sync destroy-token <sync account name>
    kanidm system sync destroy-token ipasync

Destroying the token does NOT affect the state of the sync account and it's synchronised entries. Creating
a new token and providing that to the sync tool will continue the sync process.

## Operating the Sync Tool

You should refer to the chapter for the specific external IDM system you are using for details on
the sync tool configuration.

## Finalisting the Sync Account



{{#template  
    ../templates/kani-warning.md
    imagepath=../images
    title=Warning!
    text=
}}




## Terminating the Sync Account

{{#template  
    ../templates/kani-warning.md
    imagepath=../images
    title=Warning!
    text=
}}




