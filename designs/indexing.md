## Indexing

Indexing is deeply tied to the concept of filtering. Indexes exist to make the application of a
search term (filter) faster.

## World without indexing

Almost all databases are built on top of a key-value storage engine of some nature. In our case we
are using (feb 2019) sqlite and hopefully SLED in the future.

So our entries that contain sets of avas, these are serialised into a byte format (feb 2019, json
but soon cbor) and stored in a table of "id: entry". For example:

| ID | data                                                                      |
| -- | ------------------------------------------------------------------------- |
| 01 | `{ 'Entry': { 'name': ['name'], 'class': ['person'], 'uuid': ['...'] } }` |
| 02 | `{ 'Entry': { 'name': ['beth'], 'class': ['person'], 'uuid': ['...'] } }` |
| 03 | `{ 'Entry': { 'name': ['alan'], 'class': ['person'], 'uuid': ['...'] } }` |
| 04 | `{ 'Entry': { 'name': ['john'], 'class': ['person'], 'uuid': ['...'] } }` |
| 05 | `{ 'Entry': { 'name': ['kris'], 'class': ['person'], 'uuid': ['...'] } }` |

The ID column is _private_ to the backend implementation and is never revealed to the higher level
components. However the ID is very important to indexing :)

If we wanted to find `Eq(name, john)` here, what do we need to do? A full table scan is where we
perform:

    data = sqlite.do(SELECT * from id2entry);
    for row in data:
        entry = deserialise(row)
        entry.match_filter(...) // check Eq(name, john)

For a small database (maybe up to 20 objects), this is probably fine. But once you start to get much
larger this is really costly. We continually load, deserialise, check and free data that is not
relevant to the search. This is why full table scans of any database (sql, ldap, anything) are so
costly. It's really really scanning everything!

## How does indexing work?

Indexing is a pre-computed lookup table of what you _might_ search in a specific format. Let's say
in our example we have an equality index on "name" as an attribute. Now in our backend we define an
extra table called "index_eq_name". Its contents would look like:

| index | idl (ID List) |
| ----- | ------------- |
| alan  | [03, ]        |
| beth  | [02, ]        |
| john  | [04, ]        |
| kris  | [05, ]        |
| name  | [01, ]        |

So when we perform our search for Eq(name, john) again, we see name is indexed. We then perform:

```sql
SELECT * from index_eq_name where index=john;
```

This would give us the idl (ID list) of [04,]. This is the "ID's of every entry where name equals
john".

We can now take this back to our id2entry table and perform:

```sql
data = sqlite.do(SELECT * from id2entry where ID = 04)
```

The key-value engine only gives us the entry for john, and we have a match! If id2entry had 1
million entries, a full table scan would be 1 million loads and compares - with the index, it was 2
loads and one compare. That's 30000x faster (potentially ;) )!

To improve on this, if we had a query like Or(Eq(name, john), Eq(name, kris)) we can use our indexes
to speed this up.

We would query index_eq_name again, and we would perform the search for both john, and kris. Because
this is an OR we then union the two idl's, and we would have:

```
[04, 05,]
```

Now we just have to get entries 04,05 from id2entry, and we have our matching query. This means
filters are often applied as idl set operations.

## Compressed ID lists

In order to make idl loading faster, and the set operations faster there is an idl library
(developed by me, firstyear), which will be used for this. To read more see:

https://github.com/Firstyear/idlset

## Filter Optimisation

Filter optimisation begins to play an important role when we have indexes. If we indexed something
like `Pres(class)`, then the idl for that search is the set of all database entries. Similar, if our
database of 1 million entries has 250,000 `class=person`, then `Eq(class, person)`, will have an idl
containing 250,000 ids. Even with idl compression, this is still a lot of data!

There tend to be two types of searches against a directory like Kanidm.

- Broad searches
- Targetted single entry searches

For broad searches, filter optimising does little - we just have to load those large idls, and use
them. (Yes, loading the large idl and using it is still better than full table scan though!)

However, for targeted searches, filter optimisation really helps.

Imagine a query like:

```
And(Eq(class, person), Eq(name, claire))
```

In this case with our database of 250,000 persons, our idl's would have:

```
And( idl[250,000 ids], idl(1 id))
```

Which means the result will always be the _single_ id in the idl or _no_ value because it wasn't
present.

We add a single concept to the server called the "filter test threshold". This is the state in which
a candidate set that is not completed operation, is shortcut, and we then apply the filter in the
manner of a full table scan to the partial set because it will be faster than the index loading and
testing.

When we have this test threshold, there exists two possibilities for this filter.

```
And( idl[250,000 ids], idl(1 id))
```

We load 250,000 idl and then perform the intersection with the idl of 1 value, and result in 1 or 0.

```
And( idl(1 id), idl[250,000 ids])
```

We load the single idl value for name, and then as we are below the test-threshold we shortcut out
and apply the filter to entry ID 1 - yielding a match or no match.

Notice in the second, by promoting the "smaller" idl, we were able to save the work of the idl load
and intersection as our first equality of "name" was more targeted?

Filter optimisation is about re-arranging these filters in the server using our insight to data to
provide faster searches and avoid indexes that are costly unless they are needed.

In this case, we would _demote_ any filter where Eq(class, ...) to the _end_ of the And, because it
is highly likely to be less targeted than the other Eq types. Another example would be promotion of
Eq filters to the front of an And over a Sub term, wherh Sub indexes tend to be larger and have
longer IDLs.

## Implementation Details and Notes

Before we discuss the details of the states and update processes, we need to consider the index
types we require.

# Index types

The standard index is a key-value, where the key is the lookup, and the value is the idl set of the
candidates. The examples follow the above.

For us, we will format the table names as:

- idx_eq_<attrname>
- idx_sub_<attrname>
- idx_pres_<attrname>

These will be string, blob for SQL. The string is the pkey.

We will have the Value's "to_index_str" emit the set of values. It's important to remember this is a
_set_ of possible index emissions, where we could have multiple values returned. This will be
important with claims for credentials so that the claims can be indexed correctly.

We also require a special name to uuid, and uuid to name index. These are to accelerate the
name2uuid and uuid2name functions which are common in resolving on search. These will be named in
the tables as:

- idx_name2uuid
- idx_uuid2name

They will be structured as string, string for both - where the uuid and name column matches the
correct direction, and is the primary key. We could use a single table, but if we change to sled we
need to split this, so we pre-empt this change and duplicate the data here.

# Indexing States

- Reindex

A reindex is the only time when we create the tables needed for indexing. In all other phases if we
do not have the table for the insertion, we log the error, and move on, instructing in the logs to
reindex asap.

Reindexing should be performed after we join a replication group, or when we "setup" the instance
for the first time. This means we need an "initial indexed" flag or similar.

For all intents, a reindex is likely the same as "create" but just without replacing the entry. We
would just remove all the index tables before hand.

- Write operation index metadata

At the start of a write transaction, the schema passes us a map of the current attribute index
states so that on filter application or modification we are aware of what attrs are indexed. It is
assumed that `name2uuid` and `uuid2name` are always indexed.

- Search Index Metadata

When filters are resolved they are tagged by their indexed state to allow optimisation to occur. We
then process each filter element and their tag to determine the indexes needed to built a candidate
set. Once we reach threshold we return the partial candidate set, and begin the `id2entry` process
and the `entry_match_no_index` routine.

`And` and `Or` terms have flags if they are partial or fully indexed, meaning we could have a
shortcut where if the outermost term is a full indexed term, then we can avoid the
`entry_match_no_index` Scall.

- Create

This is one of the simplest steps. On create we iterate over the entries ava's and referencing the
index metadata of the transaction, we create the indexes as needed from the values (before dbv
conversion).

- Delete

Given the Entry to delete, we remove the ava's and id's from each set as needed. Generally this will
only be for tombstones, but we still should check the process works. Important to check will be
entries with and without names, ensuring the name2uuid/uuid2name is correctly changed, and removal
of all the other attributes.

- Modify

This is the truly scary and difficult situation. The simple method would be to "delete" all indexes
based on the pre-entry state, and then to create again. However the current design of Entry and
modification doesn't work like this as we only get the Entry to add.

Most likely we will need to change modify to take the set of (pre, post) candidates as a pair _OR_
we have the entry store it's own pre-post internally. Given we already need to store the pre /post
entries in the txn, it's likely better to have a pairing of these, and that allows us to then index
replication metadata later as the entry will contain it's own changelog internally.

Given the pair, we then assert that they are the same entry (id). We can then use the index metadata
to generate an indexing diff between them, containing a set of index items to remove (due to removal
of the attr or value), and what to add (due to addition).

The major transformation cases for testing are:

- Add a multivalue (one)
- Add a multivalue (many)
- On a mulitvalue, add another value
- On multivalue, remove a value, but leave others
- Delete a multivalue
- Add a new single value
- Replace a single value
- Delete a single value

We also need to check that modification of name correctly changes name2uuid and uuid2name.

- Recycle to Tombstone (removal of name)
- Change of UUID (may happen in repl conflict scenario)
- Change of name
- Change of name and uuid

Of course, these should work as above too.
