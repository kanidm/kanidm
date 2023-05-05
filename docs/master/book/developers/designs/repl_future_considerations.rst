
Don't no-op changes
-------------------

At first glance it may seem correct to no-op a change where the state is:

{
    name: william
}

with a "purge name; add name william".

However, this doesn't express the full possibilities of the replication topology
in the system. The follow events could occur:

::

    DB 1        DB 2
    ----        ----
                del: name
                n: l
    del: name
    n: w

The events of DB 1 seem correct in isolation, to no-op the delete and re-add, however
when the changelogs will be replayed, they will then cause the events of DB2 to
be the final state - whereas the timing of events on DB 1 should actually be the
final state.

To contrast if you no-oped the purge name:

::

    DB 1        DB 2
    ----        ----
                n: l
    n: w

Your final state is now n: [l, w] - note that we have an extra name field we didn't want!



CSN
---

The CSN is a concept from 389 Directory Server. It is the Change Serial Number of a a modification
or event in the database. The CSN is a lamport clock, where it is the current time in UTC, but
it can never move *backwards*.

RID
---

The RID is a concept from 389 Directory Server. It is the Replica ID of a server. The RID must
be a unique value, that identifies exactly this server as unique.

CID
---

The CID is a (rename?) of a concept from 389 Directory Server. It is the pair of CSN and RID, allowing
for changes to now be qualified to a specific server origin and ordering between multiple servers.

As a result, this value is likely to be:

::

    (CSN, RID)

RUV
---

The RUV is a concept from 389 Directory Server. It is the replication up-to-dateness vector.

This is an array of RIDs, and their min-max CSN locations in the changelog for those RIDs. Min being the
oldest change in the log related to that RID, and max being the latest change in the log related
to that RID.

::

    Server A:
    |----------------------|
    |  ID  |  MIN  |  MAX  |
    |----------------------|
    |  01  |  000  |  010  |
    |  02  |  002  |  005  |
    |  03  |  004  |  008  |
    |----------------------|

To translate, this says that for RID 01, we have CSN 000 through 010. We can use these two values to
recreate the CID of the change itself.

Now, critically, it is important to be able to compare RUV's to determine what changes are required
to be sent, and in which order. Let's assume we have a second server with a RUV of:

::

    Server B:
    |----------------------|
    |  ID  |  MIN  |  MAX  |
    |----------------------|
    |  01  |  005  |  008  |
    |  02  |  000  |  002  |
    |  03  |  004  |  012  |
    |----------------------|

So if we are to compare these, we can see that for ID 1, Server A has 000 -> 010, and B has 005 -> 008.
You can make similar determinations for the other values.

Importantly, in this case we need to ensure the max of Server B is at least equal to or greater than our MIN for each RID.

Once we have asserting this, we can generate a list of CIDs to supply.

::

    (003,02)
    (004,02)
    (005,02)
    (009,01)
    (010,01)

It's important to note, these have been ordered by their CID, primarily by CSN! After the replication completes Server B's
RUV would now be:

::

    Server B:
    |----------------------|
    |  ID  |  MIN  |  MAX  |
    |----------------------|
    |  01  |  005  |  010  |
    |  02  |  000  |  005  |
    |  03  |  004  |  012  |
    |----------------------|

There are some other notes here: Server B is *ahead* of us for RID 3, so we actually send nothing related to
this: it's likely that Server B will connect to us later and will supply the changes 11, 12 to us.

Consider also two servers make a change at the same time. Both could generate an identical CSN
value, but due to the nature of a CID to be (CSN, RID), this means that ordering can still take
place between the events, where the server RID is now used to determine the order.


Repl Proto Ideas
----------------

We should have push based replication. There should be two versions of the system:

* Entry Level Replication
* Attribute Level Replication.

Both should be able to share the same RUV details.

Entry Based
===========

This is the simpler version of the replication system. This is likely ONLY appropriate on a read-only
consumer of data.

The read-only stores *no* server RID, and contains an initially empty RUV. The provider would then supply it's
RUV to the consumer (so that it now has a state of where it is), but with all CSN MIN/MAX set to 0.

The list of CIDs is derived by RUV comparison, but instead of supplying the change log, the entries
are sent whole, and the read-only blindly replaces them. We rely on the provider to have completed
a correct entry update resolution process for this to make sense.

To achieve this, we store a list of CID's and what entries were affected within the CID.

One can imagine a situation where two servers change the entry, but between
those changes the read-only is supplied the CID. We don't care in what order they did change,
only that a change *must* have occurred.

So example: let's take entry A with server A and B, and read-only R.

::

    A {
        data: ...
        uuid: x,
    }

    CID-list:
    [
        (001, A): [x, ...]
    ]

So the entry was created with CID (001, A). We connect to R and it has an empty RUV.

::

    RUV A:    RUV R:
    A 0/1     A 0/0

We then determine the set of CID's to transmit must be:

::

    (001, A)

Referencing our CID list, we know that uuid: x was modified, so we transmit that to the server.

Now we add server B. The ruvs now are:

::

    RUV A:    RUV B:    RUV R:
    A 0/1     A 0/1     A 0/1
    B 0/0     B 0/0

    CID-list A:
    [
        (001, A): [x, ...]
    ]

    CID-list B:
    [
        (001, A): [x, ...]
    ]

At this point a change happens on B *and* A at almost the same time: We'll say B happened first
in this case though:

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/1
    B 0/0     B 0/2

    CID-list A:
    [
        (001, A): [x, ...]
        (003, A): [x, ...]
    ]

    CID-list B:
    [
        (001, A): [x, ...]
        (002, B): [x, ...]
    ]

Remember, this protocol is ASYNC however. At this point something happens - server A replicates to R first, but
without the changes from B yet. A RUV comparison yields that RUV R must be updated with the empty RUV B, but
that the CID: (3, A) must be sent. The entry x is sent to R again.

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/3
    B 0/0     B 0/2     B 0/0

    CID-list A:
    [
        (001, A): [x, ...]
        (003, A): [x, ...]
    ]

    CID-list B:
    [
        (001, A): [x, ...]
        (002, B): [x, ...]
    ]

Now, Server B now connects to A and supplies it's changes. Since the changes on B happen *before*
the changes on A, the CID slots between the existing changes (and an update resolution would take
place, which is out of scope of this part of the design).

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/3
    B 0/2     B 0/2     B 0/0

    CID-list A:
    [
        (001, A): [x, ...]
        (002, B): [x, ...]
        (003, A): [x, ...]
    ]

Next Server A again connects to Server R, and determines based on the RUV that the differences are: (2, B).

Consulting our CID-list, we see that entry X was changed in this CID. Here's what's important: the order of the change
doesn't matter, because we take the *latest* version of UUID X, which has (1, A), (2, B) and (3, A) all
fully resolved. We send the entry X as a whole, so all state of (2, B) and LATER changes are applied.

This now means that because the whole entry was sent, we can assert the entry had changes (2, B) and
(3, A), so we can update the RUV R to:

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/3
    B 0/2     B 0/2     B 0/2

Now this protocol is not without flaws: read-only's should only be supplied data by a single server
as one could imagine the content of R flip-flopping while server A/B are not in sync. However
to prevent this situation such as:

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/3
    B 0/1     B 0/4     B 0/1

In this case, one can imagine B would then supply data, and when A Received B's changes, it would again
supply to R. However, this can be easily avoided by adhering to the following:

* A server can only supply to a read-only if all of the source server's RUV CSN MAX are contained
  within the destination RUV CSN MAX.

By following this, B would determine that as it does *not* have (3, A) (which is greater than the local
RUV CSN MAX for A), it should not supply at this time. Once A and B resolve their changes:

::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/3     A 0/3
    B 0/1     B 0/4     B 0/1

Note that B has A's changes, but not A with B's - but now, server B does satisfy the RUV conditions
and COULD supply to R. Similar, A now does not meet the conditions to supply to R until B replicates
to A. There could be a risk of starvation to R however in high write-load conditions. It could just
be preferable to allow the flip flop, but the risk there is a lack of over-all consistency of the entire
server state. This risk is minimised by the fact that we support batching of operations, so all
changes should be complete as a whole, and that if a changes happens on A in series, they must
logically be valid.


Deletion of entries is a different problem: Due to the entry lifecycle, most entries actually
step to recycled, which would trigger the above process. Similar, when recycle ends, we then
move to tombstone, again which triggers the above.

However, we must now discuss the tomstone purging process.

A tombstone would store the CID upon which it was ... well - tombstoned. As a result, the entry
itself is aware of it's state.

The tombstone purge process would work by detecting the MIN RUV of all replicas. If the MIN RUV
is greater than the tombstone CID, then it must be true that all replicas HAVE the tombstone as
a tombstone and all changes leading to that fact (as URP would dictate that all servers would
arrive at the same tombstone state). At this point, we can now safely remove the tombstone from our
database, and no replication needs to occur - as all other replicas would also remove it! This applies
to read-onlies as well.

However, this poses the question - how do we move the MIN RUV of a server? To achieve this we need
to assert that *all other servers* have at least moved past a certain state, allowing us to trim out
changelog UP TO the MIN RUV.

Let's consider the supplier to read-only situation first, as this is the simplest:

::

    RUV A:      RUV R:
    A 0/3       A 0/0

    GRUV A:
    A:R ???

To achieve this, we need to view the RUV of every server we connect to: even the RO's despite their
lack of RID (in fact this could be a reason to PROVIDE a RID to ROs) ... .
We create a global RUV (GRUV) state which would look like
the following:

::

    RUV A:      RUV R:
    A 0/3       A 0/0

    GRUV A:
    R (A: 0/0, )

So A has connected to R and polled the RUV and Received a 0/0. We now can supply our changes to
R:

::

    RUV A: -->  RUV R:
    A 0/3       A 3/3

    GRUV A:
    R (A: 0/0, )

As R is a read-only it has no concept of the changelog, so it sets MIN to MAX.

Now, we then poll the RUV again. Protocol wise RUV polling should be separate to transfer of data!

::

    RUV A:      RUV R:
    A 0/3       A 3/3

    GRUV A:
    R (A: 3/3, )

Now, we can see that the server R has changes MAX up to 3 - since this is the minimum of the set
of all MAX in GRUV, we can now purge changelog of A up to MIN 3

::

    RUV A:      RUV R:
    A 3/3       A 3/3

    GRUV A:
    R (A: 3/3, )

And we are fully consistent!

Let's imagine now we have two read-onlies, R1, R2.



::

    RUV A:    RUV B:    RUV R:
    A 0/3     A 0/1     A 0/3
    B 0/1     B 0/4     B 0/1

    GRUV A:
    A:B ???
    A:R ???

So, at this point, A would contact both


SEE ALSO: Downgrades


Attribute Level Replication
===========================

TBD





