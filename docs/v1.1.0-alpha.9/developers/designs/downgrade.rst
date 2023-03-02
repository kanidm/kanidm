Downgrades
----------

It's inevitable that someone will find some issue that requires them to downgrade
their working copy of kanidmd - that means we have to understand that process,
and at least advertise or document how it should be done.

A major barrier for us to have a downgrade process is the nature of our inplace
migrations and upgrades - while we have a system that understands how to upgrade
data and make changes, when downgrading we won't be able to understand the newer
types to do a downgrade.

Consider we add a new value type XDATA which was previous a UTF8STRING. We have
version 1.0 to 1.1. Version 1.1 will change all UTF8STRING to XDATA which is
what we want, but if we were to run version 1.0 again it would not understand
the XDATA field - not know how to downgrade since the type flatly doesn't exist.

As a result this leaves one conclusion - we can not support downgrades. Rather
the correct behaviour for us to support is to advise admins to backup before
an upgrade, and to restore from the backup if anything goes wrong.

This will affect replication in two ways

First, it means the RUV of a server node can move backwards. This requires
us to limit changelog trimming of events to events that have expired by time
rather than events that are fully resolved. This way within the changelog
trim window, a server can be downgraded, and it's RUV move backwards, but the missing updates will be "replayed" backwards to it.

Second, it means we have to consider making replication either version (typed)
data agnostic *or* have CSN's represent a dataset version from the server which gates or blocks replication events from newer to older instances until *they* are upgraded.

Having the version gate does have a good benefit. Imagine we have three servers
A, B, C. We upgrade A and B, and they migrate UTF8STRING to XDATA. Server C has
not been upgraded.

This means that *all changes* from A and B post upgrade will NOT be sent to C. C
may accept changes and will continue to provide them to A and B (provided all
other update resolution steps uphold). If we now revert B, the changes from A will
not flow to B which has been downgraded, but C's changes that were accepted WILL
continue to be accepted by B. Similar with A. This means in a downgrade scenario
that any data written on upgraded nodes that are downgraded will be lost, but
that all replication as a whole will still be valid. This is good!

It does mean we need to consider that we have to upgrade data as it comes in from
replication from an older server too to bring fields up to date if needed. This
may necesitate a "data version" field on each entry, which we can also associate
to any CSN so that it can be accepted or rejected as required.
