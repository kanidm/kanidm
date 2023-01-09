Replication Design and Notes
----------------------------

Replication is a critical feature to an IDM system, especially when deployed at major
sites and businesses. It allows for horizontal scaling of system read and write capacity,
improves fault tolerance (hardware fault, power fault, network fault, geographic disaster),
can improve client latency (positioning replicas near clients) and more.

Replication Background
======================

Replication is a directed graph model, where each node (server) and directed edge
(replication agreement) form a graph (topology). As the topology and direction can
be seen, nodes of the graph can be classified based on their data transit properties.

NOTE: Historically many replication systems used the terms "master" and "slave". This
has a number of negative cultural connotations, and is not used by this project.

* Read-Write server

This is a server that is fully writable. It accepts external client writes, and these
writes are propagated to the topology. Many read-write servers can be in a topology
and written to in parallel.

* Transport Hub

This is a server that is not writeable to clients, but can accept incoming replicated
writes, and then propagates these to other servers. All servers that are directly after
this server in the topology must not be a read-write, as writes may not propagate back
from the transport hub. IE the following is invalid

::

    RW 1 ---> HUB <--- RW 2

Note the replication direction in this, and that changes into HUB will not propagate
back to RW 1 or RW 2.

* Read-Only server

Also called a read-only replica, or in AD an RODC. This is a server that only accepts
incoming replicated changes, and has no outbound replication agreements.


Replication systems are dictated by CAP theorem. This is a theory that states from
"consistency, availability and partition tolerance" you may only have two of the
three at any time.

* Consistency

This is the property that a write to a server is guaranteed to be consistent and
acknowledged to all servers in the replication topology. A change happens on all
nodes or it does not happen at all, and clients contacting any server will always
see the latest data.

* Availability

This is the property that every request will receive a non-error response without
the guarantee that the data is "up to date".

* Partition Tolerance

This is the property that your topology in the face of partition tolerance will
continue to provide functional services (generally reads).

Almost all systems expect partition tolerance, so the choice becomes between consistency
and availability. Kanidm has chosen availability, as the needs of IDM dictate that we
always function even in the face of partition tolerance, and when other failures occur.

This AP selection is often called "eventually consistent".

Conflict Resolution
===================

As consistency is not a property that we can uphold in an AP system, we must handle
the possibility of inconsistent data and the correct methods to handle it to bring
a system into a consistent state. There are two levels that inconsistency can occur
at in a system like Kanidm.

* Object Level
* Attribute Level

Object Level inconsistency occurs when two read-write servers who are partitioned,
both allocate the same entry UUID to an entry. Since the uuid is the "primary key"
which anchors all other changes, and can not be duplicated, when the partitioning
is resolved, the replication will occur, and one of the two items must be discarded
as inconsistent.

Attribute Level inconsistency occurs within a single entry, where the same attribute
is altered by two servers who are partition. When replicated, this attribute's
state must be resolved in a manner consistent to schema of the system.

An additional complexity is that both servers must be able to resolve this
conflict in isolation, without further communication. All servers must arrive
at the same result, necesitating a set of conflict management rules that must
be the same to all members of the replication topology.

As a result, almost all facets of replication are designed around the possible
handling of these conflict cases, and tracking of changes as they occur in
a manner that allows forward and reverse application of changes.

CID
===

A CID is a change identifier. This is a compound type consisting of the domain uuid,
the server uuid, and a 64 bit timestamp. This allows selecting of changes by domain
origin, a unique server, a timerange, or a selection of these properties. This may
also be called a change serial number (CSN) in other application like 389 Directory
Server

This is so that any allocated CID is guaranteed to be unique as the timestamp generator
within a server is a lamport clock that always advances with each new write transaction.

Change
======

A single change is a CID associated to the UUID of entries that have had their state
altered in an operation. These state records are atomic units that describe a set of
changes that must occur together to be considered valid. There may be multiple state
assertions in a change.

The possible entry states are:

* NonExistent
* Live
* Recycled
* Tombstone

The possible state transitions are:

* Create
* Modify
* Recycle
* Revive
* Tombstoned
* Purge (*not changelogged!*)

A conceptual pseudocode change could be:

::

    CID: { d_uuid, s_uuid, ts }
    transitions: [
        create: uuid, entry_state { ... }
        modify: uuid, modifylist
        recycle: uuid
        tombstoned: uuid
    ]

The valid transitions are representing in a NFA, where any un-listed transition is
considered invalid and must be discarded. Transitions are consider 'in-order' within
a CID.

::

    create + NonExistent -> Live
    modify + Live -> Live
    recycle + Live -> Recycled
    revive + Recycled -> Live
    tombstoned + Recycled -> Tombstone
    purge + Tombstone -> NonExistent

.. image:: diagrams/object-lifecycle-states.png
    :width: 800

Within a single CID, in a single server, it's consider that every transition applies,
or none do.

Entry Change Log
================

Within Kanidm id2entry is the primary store of active entry state representation. However
the content of id2entry is a reflection of the series of modifications and changes that
have applied to create that entity. As a result id2entry can be considered as an entry
state cache.

The true stable storage and representation for an entry will exist in a separate Entry
Change Log type. Each entry will have it's own internal changelog that represents the
changes that have occurred in the entries lifetime and it's relevant state at that time.

The reason for making a per-entry change log is to allow fine grained testing of the
conflict resolution state machine on a per-entry scale, and then to be able to test
the higher level object behaviour above that. This will allow us to model and test
all possible states.

Changelog Index
===============

The changelog stores a series of changes associated by their CID, allowing querying
of changes based on CID properties. The changelog stores changes from multiple
server uuid's or domain uuid's, acting as a single linear history of effects on
the data of this system.

If we assume we have a single read-write server, there is no possibility of conflict
and the changelog becomes a perfect history of transitions within the database content.

We can visualise the changelog index as a series of CID's with references to the associated
entries that need to be considered. This is where we start to consider the true implementation
structure of how we will code this within Kanidm.

::

    ┌─────────────────────────────────┐             ┌─────────────────────────┐
    │ Changelog Index                 │             │ e1 - entry change log   │
    │┌───────────────────────────────┐│             │ ┌─────────────────────┐ │
    ││CID 1                          ││             │ │CID 2                │ │
    │├───────────────────────────────┤│             │ │┌───────────────────┐│ │
    ││                               ││             │ ││create: {          ││ │
    ││CID 2                          ││  ┌──────────┼─▶│    attrs          ││ │
    ││transitions {                  ││  │          │ ││}                  ││ │
    ││    create: uuid - e1, ────────┼┼──┘          │ │├───────────────────┤│ │
    ││    modify: uuid - e1, ────────┼┼─────────────┼─▶│   modify: attrs   ││ │
    ││    recycle: uuid - e2,────────┼┼──┐          │ │└───────────────────┘│ │
    ││}                              ││  │          │ └─────────────────────┘ │
    ││                               ││  │          │  ...                    │
    │├───────────────────────────────┤│  │          │                         │
    ││CID 3                          ││  │          │                         │
    │├───────────────────────────────┤│  │          └─────────────────────────┘
    ││CID 4                          ││  │
    │├───────────────────────────────┤│  │          ┌─────────────────────────┐
    ││CID 5                          ││  │          │ e2 - entry change log   │
    │├───────────────────────────────┤│  │          │ ┌─────────────────────┐ │
    ││CID 6                          ││  │          │ │CID 2                │ │
    │├───────────────────────────────┤│  │          │ │┌───────────────────┐│ │
    ││CID 7                          ││  └──────────┼─▶│recycle            ││ │
    │├───────────────────────────────┤│             │ │└───────────────────┘│ │
    ││CID 8                          ││             │ └─────────────────────┘ │
    │├───────────────────────────────┤│             │  ...                    │
    ││CID 9                          ││             │                         │
    │├───────────────────────────────┤│             └─────────────────────────┘
    ││CID 10                         ││
    │├───────────────────────────────┤│
    ││CID 11                         ││
    │├───────────────────────────────┤│
    ││CID 12                         ││
    │└───────────────────────────────┘│
    └─────────────────────────────────┘

This allows expression of both:

* An ordered set of changes globally to be applied to the set of entries
* Entries to internally maintain their set of ordered changes

Entry Snapshots
===============

Within an entry there may be many changes, and if we have an old change inserted, we need
to be able to replay those events. For example:

::

                                       ┌─────────────────────────────────┐             ┌─────────────────────────┐
                                       │ Changelog Index                 │             │ e1 - entry change log   │
    ┌───────────────────────────────┐  │                                 │             │ ┌─────────────────────┐ │
    │CID 1                         ─┼──┼─────────────▶                   │             │ │CID 2                │ │
    └───────────────────────────────┘  │┌───────────────────────────────┐│             │ │┌───────────────────┐│ │
                                       ││                               ││             │ ││create: {          ││ │
                                       ││CID 2                          ││  ┌──────────┼─▶│    attrs          ││ │
                                       ││transitions {                  ││  │          │ ││}                  ││ │
                                       ││    create: uuid - e1, ────────┼┼──┘          │ │├───────────────────┤│ │
                                       ││    modify: uuid - e1, ────────┼┼─────────────┼─▶│   modify: attrs   ││ │
                                       ││    recycle: uuid - e2,────────┼┼──┐          │ │└───────────────────┘│ │
                                       ││}                              ││  │          │ └─────────────────────┘ │
                                       ││                               ││  │          │  ...                    │
                                       │├───────────────────────────────┤│  │          │                         │
                                       ││CID 3                          ││  │          │                         │
                                       │├───────────────────────────────┤│  │          └─────────────────────────┘
                                       ││CID 4                          ││  │
                                       │├───────────────────────────────┤│  │          ┌─────────────────────────┐
                                       ││CID 5                          ││  │          │ e2 - entry change log   │
                                       │├───────────────────────────────┤│  │          │ ┌─────────────────────┐ │
                                       ││CID 6                          ││  │          │ │CID 2                │ │
                                       │├───────────────────────────────┤│  │          │ │┌───────────────────┐│ │
                                       ││CID 7                          ││  └──────────┼─▶│recycle            ││ │
                                       │├───────────────────────────────┤│             │ │└───────────────────┘│ │
                                       ││CID 8                          ││             │ └─────────────────────┘ │
                                       │├───────────────────────────────┤│             │  ...                    │
                                       ││CID 9                          ││             │                         │
                                       │├───────────────────────────────┤│             └─────────────────────────┘
                                       ││CID 10                         ││
                                       │├───────────────────────────────┤│
                                       ││CID 11                         ││
                                       │├───────────────────────────────┤│
                                       ││CID 12                         ││
                                       │└───────────────────────────────┘│
                                       └─────────────────────────────────┘


Since CID 1 has been inserted previous to CID 2 we need to "undo" the changes of CID 2 in
e1/e2 and then replay from CID 1 and all subsequent changes affecting the same UUID's to
ensure the state is applied in order correctly.

In order to improve the processing time of this operation, entry change logs need
snapshots of their entry state. At the start of the entry change log is an anchor
snapshot that describes the entry as the sum of previous changes.

::

    ┌─────────────────────────┐
    │ e1 - entry change log   │
    │ ┌─────────────────────┐ │
    │ │Anchor Snapshot      │ │
    │ │state: {             │ │
    │ │    ...              │ │
    │ │}                    │ │
    │ │                     │ │
    │ ├─────────────────────┤ │
    │ │CID 2                │ │
    │ │┌───────────────────┐│ │
    │ ││create: {          ││ │
    │ ││    attrs          ││ │
    │ ││}                  ││ │
    │ │├───────────────────┤│ │
    │ ││   modify: attrs   ││ │
    │ │└───────────────────┘│ │
    │ ├─────────────────────┤ │
    │ │Snapshot             │ │
    │ │state: {             │ │
    │ │    ...              │ │
    │ │}                    │ │
    │ │                     │ │
    │ └─────────────────────┘ │
    │  ...                    │
    │                         │
    └─────────────────────────┘

In our example here we would find the snapshot preceding our newely inserted CID (in this case
our Anchor) and from that we would then replay all subsequent changes to ensure they apply
correctly (or are rejected as conflicts).

For example if our newly inserted CID was say CID 15 then we would use the second snapshot
and we would not need to replay CID 2. These snapshots are a trade between space (disk/memory)
and replay processing time. Snapshot frequency is not yet determined. It will require measurement
and heuristic to determine an effective space/time saving. For example larger entries may want fewer
snapshots due to the size of their snapshots, where smaller entries may want more snapshots
to allow faster change replay.

Replay Processing Details
=========================

Given our CID 1 inserted prior to other CID's, we need to consider how to replay these effectively.

If CID 1 changed uuid A and B, we would add these to the active replay set. These are based on the
snapshots which are then replayed up to and include CID 1 (but no further).

From there we now proceed through the changelog index, and only consider changes that contain A or B.

Let's assume CID 3 operated on B and C. C was not considered before, and is now added to the replay
set, and the same process begins to replay A, B, C to CID 3 now.

This process continues such that the replay set is always expanding to the set of affected
entries that require processing to ensure consistency of their changes.

If a change is inconsistent or rejected, then it is rejected and marked as such in the changelog
index. Remember a future replay may allow the rejected change to be applied correctly, this rejection
is just metadata so we know what changes were not applied.

Even if a change is rejected, we still continue to assume that the entries include in that set of changes
should be consider for replay. In theory we could skip them if they were added in this change, but
it's simpler and correct to continue to consider them.

Changelog Comparison - Replication Update Vector (RUV)
======================================================

A changelog is a single servers knowledge of all changes that have occurred in history
of a topology. Of course, the point of replication is that multiple servers are exchanging
their changes, and potentially that a server must proxy changes to other servers. For this
to occur we need a method of comparing changelog states, and then allowing fractional
transmission of the difference in the sets.

To calculate this, we can use our changelog to construct a table called the replication
update vector. The RUV is a single servers changelog state, categorised by the originating
server of the change. A psudeo example of this is:

::

    |-----|--------------------|--------------------|--------------------|
    |     | {d_uuid, s_uuid A} | {d_uuid, s_uuid B} | {d_uuid, s_uuid C} |
    |-----|--------------------|--------------------|--------------------|
    | min | T4                 | T6                 | T0                 |
    |-----|--------------------|--------------------|--------------------|
    | max | T8                 | T16                | T7                 |
    |-----|--------------------|--------------------|--------------------|

Summarised, this shows that on our server, our changelog has changes from A for time range
T4 to T8, B T6 to T16, and C T0 to T7.

Individiually, a RUV does not allow much, but now we can compare RUVs to another server. Lets
assume a second server exists with the RUV of:

::

    |-----|--------------------|--------------------|--------------------|
    |     | {d_uuid, s_uuid A} | {d_uuid, s_uuid B} | {d_uuid, s_uuid C} |
    |-----|--------------------|--------------------|--------------------|
    | min | T4                 | T8                 | T0                 |
    |-----|--------------------|--------------------|--------------------|
    | max | T6                 | T10                | T11                |
    |-----|--------------------|--------------------|--------------------|

This shows the server has A T4 to T6, B TT8 to T10, and C T0 to T11. Let's assume that
we are *sending* changes from our first server to this second server. We perform a diff of the
RUV and find that for the changes of A, T7 to T8 are not present on the second server, and that
changes T11 to T16 are not present. Since C has a more "advanced" state than us, we do not
need to send anything (and later, this server should send changes to us!).

So now we know that we must send A T7 to T8 and B T11 to T16 for this replica to be brought up
to the state we hold.

You may notice the "min" and "max". The purpose of this is to show how far we may rewind our
changelog - we have changes from min to max. If a server provides it's ruv, and it's max
is lower than our min, we must consider that server has been disconnected for "too long" and
we are unable to supply changes until an administrator intervenes.

As a more graphical representation, we could consider our ruv as follows:

::

    ┌─────────────────────┐                  ┌─────────────────────────────────┐             ┌─────────────────────────┐
    │RUV                  │                  │ Changelog Index                 │             │ e1 - entry change log   │
    │┌───────────────────┐│                  │┌───────────────────────────────┐│             │ ┌─────────────────────┐ │
    ││{d_uuid, s_uuid}:  ││     ─ ─ ─ ─ ─ ─ ─▶│CID 1                          ││             │ │CID 2                │ │
    ││    min: CID 2 ────┼┼────┼─┐           │├───────────────────────────────┤│             │ │┌───────────────────┐│ │
    ││    max: CID 4 ────┼┼──────┤           ││                               ││             │ ││create: {          ││ │
    │├───────────────────┤│    │ ├───────────▶│CID 2                          ││  ┌──────────┼─▶│    attrs          ││ │
    ││{d_uuid, s_uuid}:  ││      │           ││transitions {                  ││  │          │ ││}                  ││ │
    ││    min: CID 1 ─ ─ ┼│─ ─ ┘ │           ││    create: uuid - e1, ────────┼┼──┘          │ │├───────────────────┤│ │
    ││    max: CID 8 ─ ─ ┼│─ ─ ┐ │           ││    modify: uuid - e1, ────────┼┼─────────────┼─▶│   modify: attrs   ││ │
    │├───────────────────┤│      │           ││    recycle: uuid - e2,────────┼┼──┐          │ │└───────────────────┘│ │
    ││{d_uuid, s_uuid}:  ││    │ │           ││}                              ││  │          │ └─────────────────────┘ │
    ││    min: CID 3 ────┼┼──┐   │           ││                               ││  │          │  ...                    │
    ││    max: CID 12────┼┼──┤ │ │           │├───────────────────────────────┤│  │          │                         │
    │└───────────────────┘│  ├───┼───────────▶│CID 3                          ││  │          │                         │
    └─────────────────────┘  │ │ │           │├───────────────────────────────┤│  │          └─────────────────────────┘
                             │   └───────────▶│CID 4                          ││  │
                             │ │             │├───────────────────────────────┤│  │          ┌─────────────────────────┐
                             │               ││CID 5                          ││  │          │ e2 - entry change log   │
                             │ │             │├───────────────────────────────┤│  │          │ ┌─────────────────────┐ │
                             │               ││CID 6                          ││  │          │ │CID 2                │ │
                             │ │             │├───────────────────────────────┤│  │          │ │┌───────────────────┐│ │
                             │               ││CID 7                          ││  └──────────┼─▶│recycle            ││ │
                             │ │             │├───────────────────────────────┤│             │ │└───────────────────┘│ │
                             │  ─ ─ ─ ─ ─ ─ ─▶│CID 8                          ││             │ └─────────────────────┘ │
                             │               │├───────────────────────────────┤│             │  ...                    │
                             │               ││CID 9                          ││             │                         │
                             │               │├───────────────────────────────┤│             └─────────────────────────┘
                             │               ││CID 10                         ││
                             │               │├───────────────────────────────┤│
                             │               ││CID 11                         ││
                             │               │├───────────────────────────────┤│
                             └───────────────▶│CID 12                         ││
                                             │└───────────────────────────────┘│
                                             └─────────────────────────────────┘

It may be that we also add a RUV index that allows the association of exact set of CID's to a
server's cl, or if during CL replay we just iterate through the CL index finding all values that are
greater than the set of min CID's requested in this operation.

Changelog Purging
=================

In order to prevent infinite growth of the changelog, any change older than a fixed window X
is trimmed from the changelog. When trimming occurs this moves the "min" CID in the RUV up to
a higher point in time. This also trims the entry change log and recreates a new anchor
snapshot.

RUV cleaning
============

TODO:

Conflict UUID Generation
========================

As multiple servers must arrive at the same UUID so that they are all in a deterministic
state, the UUID of a conflicting entry should be generated in a deterministic manner.

TODO:

Conflict Class
==============

TODO: Must origUUID,


Object Level Conflict Handling
===============================

With the constructs defined, we have enough in place to be able to handle various scenarioes.
For the purposes of these discussions we will present two servers with a series of changes
over time.

Let's consider a good case, where no conflict occurs.

::

        Server A                Server B
    T0:
    T1: Create E
    T2:           -- repl -->
    T3:                         Modify E
    T4:          <-- repl --

Another trivial example is the following.

::

        Server A                Server B
    T0:
    T1: Create E1
    T2:                         Create E2
    T3:           -- repl -->
    T4:          <-- repl --

These situations are clear, and valid. However, as mentioned the fun is when we have scenarios
that conflict. To resolve this, we combine the series of changes, ordered by time, and then
re-apply these changes, discarding changes that would be invalid for those states. As a reminder:

::

    create + NonExistent -> Live
    modify + Live -> Live
    recycle + Live -> Recycled
    revive + Recycled -> Live
    tombstoned + Recycled -> Tombstone
    purge(*) + Tombstone -> NonExistent

Lets now show a conflict case:

::

        Server A                Server B
    T0:
    T1: Create E1
    T2:                         Create E1
    T3:           -- repl -->
    T4:          <-- repl --

Notice that both servers create E1. In order to resolve this conflict, we use the only
synchronisation mechanism that we possess - time. On Server B at T3 when the changelog
of Server A is Received, the events are replayed, and linearised to:

::

    T0: NonExistent E1 # For illustration only
    T1: Create E1 (from A)
    T2: Create E1 (from B)

As the event at T2 can not be valid, the change at T2 is *skipped* - E1 from B is turned
into a conflict + recycled entry. See conflict UUID generation above.

In fact, having this state machine means we can see exactly what can and can not be resolved
correctly as combinations. Here is the complete list of valid combinations.

::

    T0: Create E1 (Live)
    T1: Modify E1 (Live)

    T0: Create E1 (Live)
    T1: Recycle E1 (Recycled)

    T0: Modify E1 (Live)
    T1: Modify E1 (Live)

    T0: Modify E1 (Live)
    T1: Recycle E1 (Recycled)

    T0: Recycle E1 (Recycled)
    T1: Revive E1 (Live)

    T0: Recycle E1 (Recycled)
    T1: Tombstone E1 (Tombstoned)

    T0: Revive E1 (Live)
    T1: Modify E1 (Live)

    T0: Revive E1 (Live)
    T1: Recycle E1 (Recycled)

If two items in a changelog are not a pair of these valid orderings, then we discard the
later operation.

It's worth noting that if any state of a change conflicts, the entire change is discarded
as we consider changes to be whole, atomic units of change.

Attribute Level Conflict Handling
=================================

TODO:
