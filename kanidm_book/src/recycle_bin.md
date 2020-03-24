# Recycle Bin

The recycle bin is a storage of deleted entries from the server. This allows
recovery from mistakes for a period of time.

> **WARNING:** The recycle bin is a best effort - when recovering in some cases
> not everything can be "put back" the way it was. Be sure to check your entries
> are sane once they have been revived.

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



