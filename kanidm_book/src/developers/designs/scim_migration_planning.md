
# Scim and Migration Tooling

We need to be able to synchronise content from other directory or identity management systems.
To do this, we need the capability to have "pluggable" synchronisation drivers. This is because
not all deployments will be able to use our generic versions, or may have customisations they
wish to perform that are unique to them.

To achieve this we need a layer of seperation - This effectively becomes an "extract, transform,
load" process. In addition this process must be *stateful* where it can be run multiple times
or even continuously and it will bring kanidm into synchronisation.

We refer to a "synchronisation" as meaning a complete successful extract, transform and load cycle.

There are three expected methods of using the synchronisation tools for Kanidm

* Kanidm as a "read only" portal allowing access to it's specific features and integrations. This is less of a migration, and more of a way to "feed" data into Kanidm without relying on it's internal administration features.
* "Big Bang" migration. This is where all the data from another IDM is synchronised in a single execution and applications are swapped to Kanidm. This is rare in larger deployments, but may be used in smaller sites.
* Gradual migration. This is where data is synchronised to Kanidm and then both the existing IDM and Kanidm co-exist. Applications gradually migrate to Kanidm. At some point a "final" synchronisation is performed where Kanidm 'gains authority' over all identity data and the existing IDM is disabled.

In these processes there may be a need to "reset" the synchronsied data. The diagram below shows the possible work flows which account for the above.

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
    │  │   Initial   │      │   │   Partial   │       │   │    Final    │  │
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

For Kanidm as a "read only" application source the Initial synchronisation is performed followed by periodic
partial synchronisations. At anytime a full initial synchronisation can re-occur to reset the data of the
provider. The provider can be reset and removed by a purge which reset's Kanidm to a detached state.

For a gradual migration, this process is the same as the read only application. However when ready
to perform the final cut over a final synchronisation is performed, which retains the data of the
external system and grants Kanidm the authority over it. This then moves Kanidm back to the detached
state, but with a full cope of the provider data.

A "big bang" migration is this same process, but the "final" synchronisation is the first and only
step required, where all data is loaded and then immediately granted authority to Kanidm.

## ETL process

### Extract

First a user must be able to retrieve their data from their supplying IDM source. Initially
we will target LDAP and systems with LDAP interfaces, but in the future there is no barrier
to supporting other transports.

To achieve this, we initially provide synchronisation primitives in the
[ldap3 crate](https://github.com/kanidm/ldap3).

### Transform

This process will be custom developed by the user, or may have a generic driver that we provide.
Our generic tools may provide attribute mapping abilitys so that we can allow some limited
customisation.

### Load

Finally to load the data into Kanidm, we will make a SCIM interface available. SCIM is a
"spiritual successor" to LDAP, and aligns with Kani's design. SCIM allows structured data
to be uploaded (unlike LDAP which is simply strings). Because of this SCIM will allow us to
expose more complex types that previously we have not been able to provide.

The largest benefit to SCIM's model is it's ability to perform "batched" operations, which work
with Kanidm's transactional model to ensure that during load events, that content is always valid
and correct.

## Configuring a Synchronisation Provider in Kanidm

Kanidm has a strict transactional model with full ACID compliance. Attempting to create an external
model that needs to interoperate with Kanidm's model and ensure both are compliant is fraught with
danger. As a result, Kanidm sync providers *should* be stateless, acting only as an ETL bridge.

Additionally syncproviders need permissions to access and write to content in Kanidm, so it also
necessitates Kanidm being aware of the sync relationship.

For this reason a syncprovider is a derivative of a service account, which also allows storage of
the *state* of the synchronisation operation. An example of this is that LDAP syncrepl provides a
cookie defining the "state" of what has been "consumed up to" by the ETL bridge. During the
load phase the modified entries *and* the cookie are persisted. This means that if the operation fails
the cookie also rolls back allowing a retry of the sync. If it suceeds the next sync knows that
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

At any point the operation *may* fail, so by locking the state with the upload of entries this
guarantees correct upload has suceeded and persisted. A success really means it!

## SCIM

### Authentication to the endpoint

This will be based on Kanidm's existing authentication infrastructure, allowing service accounts
to use bearer tokens. These tokens will internally bind that changes from the account MUST contain
the associated state identifier (cookie).

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

