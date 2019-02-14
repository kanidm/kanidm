
Entries
-------

Entries are the base unit of data in this server. This is one of the three foundational concepts
along with filters and schema that everything thing else builds upon.

What is an Entry?
-----------------

An entry is a collection of attribute-values. These are sometimes called attribute-value-assertions,
attr-value sets. The attribute is a "key", and it holds 1 to infinite values associated. An entry
can have many avas associated, which creates the entry as a whole. An example entry (minus schema):

    Entry {
        "name": ["william"],
        "mail": ["william@email", "email@william"],
        "uuid": ["..."],
    }

There are only a few rules that are true in entries.

* UUID

All entries *must* have a UUID attribute, and there must ONLY exist a single value. This UUID ava
MUST be unique within the database, regardless of entry state (live, recycled, tombstoned etc).

* Zero values

An attribute with zero values, is removed from the entry.

* Unsorted

Values within an attribute are "not sorted" in any meaningful way for a client utility (in reality
they are sorted by an undefined internal order for fast lookup/insertion).


That's it.
