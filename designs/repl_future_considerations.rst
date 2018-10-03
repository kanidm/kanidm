
Don't no-op changes
-------------------

At first glance it may seem correct to no-op a change where the state is:

{
    name: william
}

with a "delete name; add name william".

However, this doesn't express the full possibities of the replication topology
in the system. The follow events could occur:

::

    DB 1        DB 2
    ----        ----
    n: w
                del: name
                n: l
    del: name
    n: w

The events of DB 1 seem correct in isolation, to no-op the del and re-add, however
when the changelogs will be replayed, they will then cause the events of DB2 to
be the final state - whet the timing of events on DB 1 should actually be the
final state.
