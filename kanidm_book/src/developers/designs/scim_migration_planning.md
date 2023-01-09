# Scim and Migration Tooling

We need to be able to synchronise content from other directory or identity management systems. To do
this, we need the capability to have "pluggable" synchronisation drivers. This is because not all
deployments will be able to use our generic versions, or may have customisations they wish to
perform that are unique to them.

To achieve this we need a layer of separation - This effectively becomes an "extract, transform,
load" process. In addition this process must be _stateful_ where it can be run multiple times or
even continuously and it will bring kanidm into synchronisation.

We refer to a "synchronisation" as meaning a complete successful extract, transform and load cycle.

There are three expected methods of using the synchronisation tools for Kanidm

- Kanidm as a "read only" portal allowing access to it's specific features and integrations. This is
  less of a migration, and more of a way to "feed" data into Kanidm without relying on it's internal
  administration features.
- "Big Bang" migration. This is where all the data from another IDM is synchronised in a single
  execution and applications are swapped to Kanidm. This is rare in larger deployments, but may be
  used in smaller sites.
- Gradual migration. This is where data is synchronised to Kanidm and then both the existing IDM and
  Kanidm co-exist. Applications gradually migrate to Kanidm. At some point a "final" synchronisation
  is performed where Kanidm 'gains authority' over all identity data and the existing IDM is
  disabled.

In these processes there may be a need to "reset" the synchronsied data. The diagram below shows the
possible work flows which account for the above.

                              ┏━━━━━━━━━━━━━━━━━┓
                              ┃                 ┃
                              ┃    Detached     ┃
    ┌──────────────────────┬──┃ (Initial State) ┃◀─────────────────────────┐
    │                      │  ┃                 ┃                          │
    │                      │  ┗━━━━━━━━━━━━━━━━━┛                          │
    │                      └──────────────────────────┐                    │
    │                                                 │                    │
    ├───────────────────────┬─────────────────────┐   │                    │
    │  ┌─────────────┐      │   ┌─────────────┐   │   │   ┌─────────────┐  │
    │  │             │      │   │             │───┘   │   │             │  │
    │  │   Initial   │      │   │   Active    │       │   │    Final    │  │
    └─▶│ Synchronise │──────┴──▶│ Synchronise │───────┴──▶│ Synchronise │──┤
       │             │          │             │           │             │  │
       └─────────────┘          └─────────────┘           └─────────────┘  │
              │                        │                                   │
              │                        │                  ┌─────────────┐  │
              │                        │                  │             │  │
              │                        │                  │    Purge    │  │
              └────────────────────────┴─────────────────▶│   Content   │──┘
                                                          │             │
                                                          └─────────────┘

Kanidm starts in a "detached" state from the extern IDM source.

For Kanidm as a "read only" application source the Initial synchronisation is performed followed by
periodic active (partial) synchronisations. At anytime a full initial synchronisation can re-occur
to reset the data of the provider. The provider can be reset and removed by a purge which reset's
Kanidm to a detached state.

For a gradual migration, this process is the same as the read only application. However when ready
to perform the final cut over a final synchronisation is performed, which retains the data of the
external system and grants Kanidm the authority over it. This then moves Kanidm back to the detached
state, but with a full cope of the provider data.

A "big bang" migration is this same process, but the "final" synchronisation is the first and only
step required, where all data is loaded and then immediately granted authority to Kanidm.

## ETL process

### Extract

First a user must be able to retrieve their data from their supplying IDM source. Initially we will
target LDAP and systems with LDAP interfaces, but in the future there is no barrier to supporting
other transports.

To achieve this, we initially provide synchronisation primitives in the
[ldap3 crate](https://github.com/kanidm/ldap3).

### Transform

This process will be custom developed by the user, or may have a generic driver that we provide. Our
generic tools may provide attribute mapping abilitys so that we can allow some limited
customisation.

### Load

Finally to load the data into Kanidm, we will make a SCIM interface available. SCIM is a "spiritual
successor" to LDAP, and aligns with Kani's design. SCIM allows structured data to be uploaded
(unlike LDAP which is simply strings). Because of this SCIM will allow us to expose more complex
types that previously we have not been able to provide.

The largest benefit to SCIM's model is it's ability to perform "batched" operations, which work with
Kanidm's transactional model to ensure that during load events, that content is always valid and
correct.

## Configuring a Synchronisation Provider in Kanidm

Kanidm has a strict transactional model with full ACID compliance. Attempting to create an external
model that needs to interoperate with Kanidm's model and ensure both are compliant is fraught with
danger. As a result, Kanidm sync providers _should_ be stateless, acting only as an ETL bridge.

Additionally syncproviders need permissions to access and write to content in Kanidm, so it also
necessitates Kanidm being aware of the sync relationship.

For this reason a syncprovider is a derivative of a service account, which also allows storage of
the _state_ of the synchronisation operation. An example of this is that LDAP syncrepl provides a
cookie defining the "state" of what has been "consumed up to" by the ETL bridge. During the load
phase the modified entries _and_ the cookie are persisted. This means that if the operation fails
the cookie also rolls back allowing a retry of the sync. If it succeeds the next sync knows that
kanidm is in the correct state. Graphically:

    ┌────────────┐                    ┌────────────┐                   ┌────────────┐
    │            │                    │            │     Retrieve      │            │
    │            │                    │            │──────Cookie──────▶│            │
    │            │                    │            │                   │            │
    │            │                    │            │    Provide        │            │
    │            │                    │            │◀────Cookie────────│            │
    │            │   Sync Request     │            │                   │            │
    │  External  │◀───With Cookie─────│    ETL     │                   │            │
    │    IDM     │                    │   Bridge   │                   │   Kanidm   │
    │            │   Sync Response    │            │                   │            │
    │            │────New Cookie─────▶│            │                   │            │
    │            │                    │            │                   │            │
    │            │                    │            │  Upload Entries   │            │
    │            │                    │            │──Persist Cookie──▶│            │
    │            │                    │            │                   │            │
    │            │                    │            │◀─────Result───────│            │
    └────────────┘                    └────────────┘                   └────────────┘

At any point the operation _may_ fail, so by locking the state with the upload of entries this
guarantees correct upload has succeeded and persisted. A success really means it!

## SCIM

### Authentication to the endpoint

This will be based on Kanidm's existing authentication infrastructure, allowing service accounts to
use bearer tokens. These tokens will internally bind that changes from the account MUST contain the
associated state identifier (cookie).

### Batch Operations

Per [rfc7644 section 3.7](https://datatracker.ietf.org/doc/html/rfc7644#section-3.7)

A requirement of the sync account will be a PATCH request to update the state identifier as the
first operation of the batch request. Failure to do so will result in an error.

### Schema and Attributes

SCIM defines a number of "generic" schemas for User's and Group's. Kanidm will provide it's own
schema definitions that extend or replace these. TBD.

## Post Migration Concerns

### Reattaching a Provider Post Final Sync

In the case that a provider is re-attached after it has been through a final synchronisation,
entries that Kanidm now has authority over will NOT be synced and will be highlighted as conflicts.
The administrator then needs to decide how to proceed with these conflicts determining which data
source is the authority on the information.

## Internal Batch Update Operation Phases

We have to consider in our batch updates that there are multiple stages of the update. This is
because we need to consider that at any point the lifecycle of a presented entry may change within a
single batch. Because of this, we have to treat the operation differently within kanidm to ensure a
consistent outcome.

Additionally we have to "fail fast". This means that on any conflict the sync will abort and the
administrator must intervene.

To understand why we chose this, we have to look at what happens in a "soft fail" condition.

In this example we have an account named X and a group named Y. The group contains X as a member.

When we submit this for an initial sync, or after the account X is created, if we had a "soft" fail
during the import of the account, we would reject it from being added to Kanidm but would then
continue with the synchronisation. Then the group Y would be imported. Since the member pointing to
X would not be valid, it would be silently removed.

At this point we would have group Y imported, but it has no members and the account X would not have
been imported. The administrator may intervene and fix the account X to allow sync to proceed.
However this would not repair the missing group membership. To repair the group membership a change
to group Y would need to be triggered to also sync the group status.

Since the admin may not be aware of this, it would silently mean the membership is missing.

To avoid this, by "failing fast" if account X couldn't be imported for any reason, than we would
stop the whole sync process until it could be repaired. Then when repaired both the account X and
group Y would sync and the membership would be intact.

### Phase 1 - Validation of Update State

In this phase we need to assert that the batch operation can proceed and is consistent with the
expectations we have of the server's state.

Assert the token provided is valid, and contains the correct access requirements.

From this token, retrieve the related synchronisation entry.

Assert that the batch updates from and to state identifiers are consistent with the synchronisation
entry.

Retrieve the sync\_parent\_uuid from the sync entry.

Retrieve the sync\_authority value from the sync entry.

### Phase 2 - Entry Location, Creation and Authority

In this phase we are ensuring that all the entries within the operation are within the control of
this sync domain. We also ensure that entries we intend to act upon exist with our authority markers
such that the subsequent operations are all "modifications" rather than mixed create/modify

For each entry in the sync request, if an entry with that uuid exists retrieve it.

- If an entry exists in the database, assert that it's sync\_parent\_uuid is the same as our
  agreements.
  - If there is no sync\_parent\_uuid or the sync\_parent\_uuid does not match, reject the
    operation.

- If no entry exists in the database, create a "stub" entry with our sync\_parent\_uuid
  - Create the entry immediately, and then retrieve it.

### Phase 3 - Entry Assertion

Remove all attributes in the sync that are overlapped with our sync\_authority value.

For all uuids in the entry present set Assert their attributes match what was synced in. Resolve
types that need resolving (name2uuid, externalid2uuid)

Write all

### Phase 4 - Entry Removal

For all uuids in the delete\_uuids set: if their sync\_parent\_uuid matches ours, assert they are
deleted (recycled).

### Phase 5 - Commit

Write the updated "state" from the request to\_state to our current state of the sync

Write an updated "authority" value to the agreement of what attributes we can change.

Commit the txn.
