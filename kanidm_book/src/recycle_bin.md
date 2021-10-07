# Recycle Bin

The recycle bin is a storage of deleted entries from the server. This allows
recovery from mistakes for a period of time.

> **WARNING:** The recycle bin is a best effort - when recovering in some cases
> not everything can be "put back" the way it was. Be sure to check your entries
> are valid once they have been revived.

## Where is the Recycle Bin?

The recycle bin is stored as part of your main database - it is included in all
backups and restores, just like any other data. It is also replicated between
all servers.

## How do things get into the Recycle Bin?

Any delete operation of an entry will cause it to be sent to the recycle bin. No
configuration or specification is required.

## How long do items stay in the Recycle Bin?

Currently they stay up to 1 week before they are removed.

## Managing the Recycle Bin

You can display all items in the Recycle Bin with:

    kanidm recycle_bin list --name admin

You can show a single items with:

    kanidm recycle_bin get --name admin <id>

An entry can be revived with:

    kanidm recycle_bin revive --name admin <id>

## Edge cases

The recycle bin is a best effort to restore your data - there are some cases where
the revived entries may not be the same as their were when they were deleted. This
generally revolves around reference types such as group membership, or when the reference
type includes supplemental map data such as the oauth2 scope map type.

An example of this data loss is the following steps:

    add user1
    add group1
    add user1 as member of group1
    delete user1
    delete group1
    revive user1
    revive group1

In this series of steps, due to the way that referential integrity is implemented, the
membership of user1 in group1 would be lost in this process. To explain why:

    add user1
    add group1
    add user1 as member of group1 // refint between the two established, and memberof added
    delete user1 // group1 removes member user1 from refint
    delete group1 // user1 now removes memberof group1 from refint
    revive user1 // re-add groups based on directmemberof (empty set)
    revive group1 // no members

These issues could be looked at again in the future, but for now we think that deletes of
groups is rare - we expect recycle bin to save you in "opps" moments, and in a majority
of cases you may delete a group or a user and then restore them. To handle this series
of steps requires extra code complexity in how we flag operations. For more,
see [This issue on github](https://github.com/kanidm/kanidm/issues/177).

