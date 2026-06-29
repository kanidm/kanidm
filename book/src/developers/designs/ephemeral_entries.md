# Ephemeral Entries

We have a number of data types and entries that may need to be automatically deleted
after some time window has past. This could be an event notification, a group for a
temporary group membership, a session token, or more.

To achieve this we need a way to mark entries as ephemeral. After a set time has past
the entry will be automatically deleted.

## Class

A new class `EphemeralObject` will be added. It will have a must attribute of `removedAt`
which will contain a time at which the entry will be deleted.

## Automatic Deletion

A new interval task similar to the recycle/tombstone tasks will be added that checks for
and deletes ephemeral objects once removedAt has past.

## Ordering Index

To make this effecient we should consider addition of an "ordering" index on the `removedAt`
attribute to improve searching for these. Initially this won't be needed as there will be
very few of these, but it should be added in future.
