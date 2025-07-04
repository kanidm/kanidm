# Replication Design and Notes

Replication is a critical feature in an IDM system, especially when deployed at major sites and businesses. It allows
for horizontal scaling of system read and write capacity, improves fault tolerance (hardware, power, network,
environmental), and can improve client latency (by positioning replicas near clients).

## Replication Background

Replication is a directed graph model, where each node (server) and directed edge (replication agreement) form a graph
(topology). As the topology and direction can be seen, nodes of the graph can be classified based on their data transit
properties.

NOTE: Historically many replication systems used the terms "master" and "slave". This has a number of negative cultural
connotations, and is not used by this project.

### Read-Write server

This is a server that is fully writable. It accepts external client writes, and these writes are propagated to the
topology. Many read-write servers can be in a topology and written to in parallel.

### Transport Hub

This is a server that is not writeable to clients, but can accept incoming replicated writes, and then propagates these
to other servers. All servers that are directly after this server in the topology must not be a read-write, as writes
may not propagate back from the transport hub. IE the following is invalid

    RW 1 ---> HUB <--- RW 2

Note the replication direction in this, and that changes into HUB will not propagate back to RW 1 or RW 2.

### Read-Only server

Also called a read-only replica, or in AD an RODC. This is a server that only accepts incoming replicated changes, and
has no outbound replication agreements.

Replication systems are dictated by CAP theorem. This is a theory that states from "consistency, availability and
partition tolerance" you may only have two of the three at any time.

### Consistency

This is the property that a write to a server is guaranteed to be consistent and acknowledged to all servers in the
replication topology. A change happens on all nodes or it does not happen at all, and clients contacting any server will
always see the latest data.

### Availability

This is the property that every request will receive a non-error response without the guarantee that the data is "up to
date".

### Partition Tolerance

This is the property that your topology in the face of partition tolerance will continue to provide functional services
(generally reads).

Almost all systems expect partition tolerance, so the choice becomes between consistency and availability. These create
a series of tradeoffs. Choosing consistency normally comes at significantly reduced write throughput due to the need for
a majority of nodes to acknowledge changes. However, it avoids a need for complex conflict resolution systems. It also
means that clients can be in a situation where they can't write. For IDM this would mean new sessions could not be
created or accounts locked for security reasons.

Kanidm has chosen availability, as the needs of IDM dictate that we always function even in the face of partition
tolerance, and when other failures occur. This comes at the cost of needing to manage conflict resolution. This AP
selection is often called "eventually consistent" as nodes will convenge to an identical state over time.

## Replication Phases

There are two phases of replication

1. Refresh

This is when the content of a node is completely removed, and has the content of another node applied to replace it. No
conflicts or issues can occur in this, as the refreshed node is now a "perfect clone" of the source node.

2. Incremental

This is when differentials of changes are sent between nodes in the topology. By sending small diffs, it saves bandwidth
between nodes and allows changes on all nodes to be merged and combined with other nodes. It is the handling of these
incremental updates that can create conflicts in the data of the server.

## Ordering of Writes - Change Identifiers

Rather than using an external coordinator to determine consistency, time is used to determine ordering of events. This
allows any server to create a total-ordering of all events as though every write had occurred on a single server. This
is how all nodes in replication will "arrive" at the same conclusion about data state, without the need for
communication.

In order for time to be used in this fashion, it is important that the clock in use is always _advancing_ and never
stepping backwards. If a clock was to go backwards, it would cause an event on one node to be written in a different
order than the way that other servers will apply the same writes. This creates data corruption.

As an aside, there _are_ systems that do replication today and _do not_ use always advancing clocks which can allow data
corruption to seep in.

In addition it's also important that if an event happens at exactly the same moment on two nodes (down to the
nanosecond) that a way of breaking the tie exists. This is why each server has an internal uuid, where the server uuid
is used to order events if the timestamps are identical.

These points in time are represented by a changed identifier that contains the time of the event, and the server uuid
that performed the event. In addition every write transaction of the server records the current time of the transaction,
and if a subsequent transaction starts with a "time in the past", then the time is "dragged forward" to one nanosecond
after the former transaction. This means CID's always advance - and never go backwards.

## Conflict Resolution

Despite the ability to order writes by time, consistency is not a property that we can guarantee in an AP system. we
must be able to handle the possibility of inconsistent data and the correct methods to bring all nodes into a consistent
state with cross communication. These consistency errors are called conflicts. There are multiple types of conflict that
can occur in a system like Kanidm.

### Entry Conflicts

This is when the UUID of an entry is duplicated on a separate node. For example, two entries with UUID=A are created at
the same time on two separate nodes. During replication one of these two nodes will persist and the other will become
conflicted.

### Attribute Conflicts

When entries are updated on two nodes at the same time, the changes between the entries need to be merged. If the same
attribute is updated on two nodes at the same time the differences need to be reconciled. There are three common levels
of resolution used for this. Lets consider an entry such as:

    # Node A
    attr_a: 1
    attr_b: 2
    attr_c: 3

    # Node B
    attr_b: 1
    attr_c: 2
    attr_d: 3

- Object Level

In object level resolution the entry that was "last written wins". The whole content of the last written entry is used,
and the earlier write is lost.

In our example, if node B was the last write the entry would resolve as:

    # OL Resolution
    attr_b: 1
    attr_c: 2
    attr_d: 3

- Attribute Level

In attribute level resolution, the time of update for each attribute is tracked. If an attribute was written later, the
content of that attribute wins over the other entries.

For example, if attr b was written last on node B, and attr c was written last on node A then the entry would resolve
to:

    # AL Resolution
    attr_a: 1  <- from node A
    attr_b: 1  <- from node B
    attr_c: 3  <- from node A
    attr_d: 3  <- from node B

- Value Level

In value level resolution, the values of each attribute is tracked for changes. This allows values to be merged,
depending on the type of attribute. This is the most "consistent" way to create an AP system, but it's also the most
complex to implement, generally requiring a changelog of entry states and differentials for sequential reapplication.

Using this, our entries would resolve to:

    # VL Resolution
    attr_a: 1
    attr_b: 1, 2
    attr_c: 2, 3
    attr_d: 3

Each of these strategies has pros and cons. In Kanidm we have used a modified attribute level strategy where individual
attributes can internally perform value level resolution if needed in limited cases. This allows fast and simple
replication, while still allowing the best properties of value level resolution in limited cases.

### Schema Conflicts

When an entry is updated on two nodes at once, it may be possible that the updates on each node individually are valid,
but when combined create an inconsistent entry that is not valid with respect to the schema of the server.

### Plugin Conflicts

Kanidm has a number of "plugins" that can enforce logical rules in the database such as referential integrity and
attribute uniqueness. In cases that these rules are violated due to incremental updates, the plugins in some cases can
repair the data. However in cases where this can not occur, entries may become conflicts.

## Tracking Writes - Change State

To track these writes, each entry contains a hidden internal structure called a change state. The change state tracks
when the entry was created, when any attribute was written to, and when the entry was deleted.

The change state reflects the lifecycle of the entry. It can either be:

- Live
- Tombstoned

A live entry is capable of being modified and written to. It is the "normal" state of an entry in the database. A live
entry contains an "origin time" or "created at" timestamp. This allows unique identification of the entry when combined
with the uuid of the entry itself.

A tombstoned entry is a "one way street". This represents that the entry at this uuid is _deleted_. The tombstone
propagates between all nodes of the topology, and after a tombstone window has passed, is reaped by all nodes
internally.

A live entry also contains a map of change times. This contains the maximum CID of when an attribute of the entry was
updated last. Consider an entry like:

    attr_a: 1
    attr_b: 2
    attr_c: 3
    uuid:   X

This entries changestate would show:

    Live {
      at: { server_uuid: A, cid: 1 },
      attrs: {
        attr_a: cid = 1
        attr_b: cid = 1
        attr_c: cid = 2
      }
    }

This shows us that the entry was created on server A, at cid time 1. At creation, the attributes a and b were created
since they have the same cid.

attr c was either updated or created after this - we can't tell if it existed at cid 1, we can only know that a write of
some kind occurred at cid 2.

## Resolving Conflicts

With knowledge of the change state structure we can now demonstrate how the lower level entry and attribute conflicts
are detected and managed in Kanidm.

### Entry

An entry conflict occurs when two servers create an entry with the same UUID at the same time. This would be shown as:

            Server A            Server B
    Time 0: create entry X
    Time 1:                     create entry X
    Time 2:       <-- incremental --
    Time 3:        -- incremental -->

We can add in our entry change state for liveness here.

    Time 0: create entry X cid { time: 0, server: A }
    Time 1:                     create entry X cid { time: 1, server: B }
    Time 2:       <-- incremental --
    Time 3:        -- incremental -->

When the incremental occurs at time point 2, server A would consider these on a timeline as:

    Time 0: create entry X cid { time: 0, server: A }
    Time 1: create entry X cid { time: 1, server: B }

When viewed like this, we can see that if the second create had been performed on the same server, it would have been
rejected as a duplicate entry. With replication enabled, this means that the latter entry will be moved to the conflict
state instead.

The same process occurs with the same results when the reverse incremental operation occurs to server B where it
receives the entry with the earlier creation from A. It will order the events and "conflict" its local copy of the
entry.

### Attribute

An attribute conflict occurs when two servers modify the same attribute of the same entry before an incremental
replication occurs.

            Server A            Server B
    Time 0: create entry X
    Time 1:        -- incremental -->
    Time 2: modify entry X
    Time 3:                     modify entry X
    Time 4:       <-- incremental --
    Time 5:        -- incremental -->

During an incremental operation, a modification to a live entry is allowed to apply provided the entries UUID and AT
match the servers metadata. This gives the servers assurance that an entry is not in a conflict state, and that the node
applied the change to the same entry. Were the AT values not the same, then the entry conflict process would be applied.

We can expand the metadata of the modifications to help understand the process here for the attribute.

            Server A            Server B
    Time 0: create entry X
    Time 1:        -- incremental -->
    Time 2:                     modify entry X attr A cid { time: 2, server: B }
    Time 3: modify entry X attr A cid { time: 3, server: A }
    Time 4:       <-- incremental --
    Time 5:        -- incremental -->

When the incremental is sent in time 4 from B to A, since the modification of the attribute is earlier than the content
of A, the incoming attribute state is discarded. (A future version of Kanidm may preserve the data instead).

At time 5 when the increment returns from A to B, the higher cid causes the value of attr A to be replaced with the
content from server A.

This allows all servers to correctly order and merge changes between nodes.

### Schema

An unlikely but possible scenario is a set of modifications that create incompatible entry states with regard to schema.
For example:

            Server A            Server B
    Time 0: create group X
    Time 1:        -- incremental -->
    Time 2: modify group X into person X
    Time 3:                     modify group X attr member
    Time 4:       <-- incremental --
    Time 5:        -- incremental -->

It is rare (if not will never happen) that an entry is morphed in place from a group to a person, from one class to a
fundamentally different class. But the possibility exists so we must account for it.

In this case, what would occur is that the attribute of 'member' would be applied to a person, which is invalid for the
kanidm schema. In this case, the entry would be moved into a conflict state since logically it is not valid for
directory operations (even if the attributes and entry level replication requirements for consistency have been met).

### Plugin

Finally, plugins allow enforcement of rules above schema. An example is attribute uniqueness. Consider the following
operations.

            Server A            Server B
    Time 0: create entry X      create entry Y
    Time 1:        -- incremental -->
    Time 2:       <-- incremental --
    Time 3: modify entry X attr name = A
    Time 4:                     modify entry Y attr name = A
    Time 5:       <-- incremental --
    Time 6:        -- incremental -->

Here the entry is valid per the entry, attribute and schema rules. However, name is a unique attribute and can not have
duplicates. This is the most likely scenario for conflicts to occur, since users can rename themself at any time.

In this scenario, in the incremental replication both entry Y and X would be move to the conflict state. This is because
the name attribute may have been updated multiple times, or between incremental operations, meaning that either server
can not reliably determine if X or Y is valid at _this_ point in time, and wrt to future replications.

## Incremental Replication

To this point, we have described "refresh" as a full clone of data between servers. This is easy to understand, and
works as you may expect. The full set of all entries and their changestates are sent from a supplier to a consumer,
replacing all database content on the consumer.

Incremental replication however requires knowledge of the state of the consumer and supplier to determine a difference
of the entries between the pair.

To achieve this each server tracks a replication update vector (RUV), that describes the _range_ of changes organised
per server that originated the change. For example, the RUV on server B may contain:

    |-----|----------|----------|
    |     | s_uuid A | s_uuid B |
    |-----|----------|----------|
    | min | T4       | T6       |
    |-----|----------|----------|
    | max | T8       | T16      |
    |-----|----------|----------|

This shows that server B contains the set of data ranging _from_ server A at time 4 and server B at time 6 to the latest
values of server A at time 8 and server B at time 16.

During incremental replication the consumer sends it RUV to the supplier. The supplier calculates the _difference_
between the consumer RUV and the supplier RUV. For example,

    Server A RUV                   Server B RUV
    |-----|----------|----------|  |-----|----------|----------|
    |     | s_uuid A | s_uuid B |  |     | s_uuid A | s_uuid B |
    |-----|----------|----------|  |-----|----------|----------|
    | min | T4       | T6       |  | min | T4       | T6       |
    |-----|----------|----------|  |-----|----------|----------|
    | max | T10      | T16      |  | max | T8       | T20      |
    |-----|----------|----------|  |-----|----------|----------|

If A was the supplier, and B the consumer, when comparing these RUV's Server A would determine that B required the
changes `A {T9, T10}`. Since B is ahead of A wrt to the server B changes, server A would not supply these ranges. In the
reverse, B would supply `B {T17 -> T20}`.

If there were multiple servers, this allows replicas to _proxy_ changes.

    Server A RUV                              Server B RUV
    |-----|----------|----------|----------|  |-----|----------|----------|----------|
    |     | s_uuid A | s_uuid B | s_uuid C |  |     | s_uuid A | s_uuid B | s_uuid C |
    |-----|----------|----------|----------|  |-----|----------|----------|----------|
    | min | T4       | T6       | T5       |  | min | T4       | T6       | T4       |
    |-----|----------|----------|----------|  |-----|----------|----------|----------|
    | max | T10      | T16      | T13      |  | max | T8       | T20      | T8       |
    |-----|----------|----------|----------|  |-----|----------|----------|----------|

In this example, if A were supplying to B, then A would supply `A {T9, T10}` and `C {T9 -> T13}`. This allows the
replication to avoid full connection (where every node must contact every other node).

In order to select the entries for supply, the database maintains an index of entries that are affected by any change
for any cid. This allows range requests to be made for efficient selection of what entries were affected in any cid.

After an incremental replication is applied, the RUV is updated to reflect the application of these differences.

## Lagging / Advanced Consumers

Replication relies on each node periodically communicating for incremental updates. This is because of _deletes_. A
delete event occurs by a Live entry becoming a Tombstone. A tombstone is replicated over the live entry. Tombstones are
then _reaped_ by each node individually once the replication delay window has passed.

This delay window is there to allow every node the chance to have the tombstone replicated to it, so that all nodes will
delete the tombstone at a similar time.

Once the delay window passes, the RUV is _trimmed_. This moves the RUV minimum.

We now need to consider the reason for this trimming process. Lets use these RUV's

    Server A RUV                   Server B RUV
    |-----|----------|----------|  |-----|----------|----------|
    |     | s_uuid A | s_uuid B |  |     | s_uuid A | s_uuid B |
    |-----|----------|----------|  |-----|----------|----------|
    | min | T10      | T6       |  | min | T4       | T9       |
    |-----|----------|----------|  |-----|----------|----------|
    | max | T15      | T16      |  | max | T8       | T20      |
    |-----|----------|----------|  |-----|----------|----------|

The RUV for A on A does not overlap the range of the RUV for A on B (A min 10, B max 8).

This means that a tombstone _could_ have been created at T9 _and then_ reaped. This would mean that B would not have
perceived that delete and then the entry would become a zombie - back from the dead, risen again, escaping the grave,
breaking the tombstone. This could have security consequences especially if the entry was a group providing access or a
user who was needing to be deleted.

To prevent this, we denote server B as _lagging_ since it is too old. We denote A as _advanced_ since it has data newer
that can not be applied to B.

This will "freeze" B, where data will not be supplied to B, nor will data from B be accepted by other nodes. This is to
prevent the risk of data corruption / zombies.

There is some harm to extending the RUV trim / tombstone reaping window. This window could be expanded even to values as
long as years. It would increase the risk of conflicting changes however, where nodes that are segregated for extended
periods have been accepting changes that may conflict with the other side of the topology.
