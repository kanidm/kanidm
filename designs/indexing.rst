
Indexing
--------

Indexing is deeply tied to the concept of filtering. Indexes exist to make the application of a
search term (filter) faster.

World without indexing
----------------------

Almost all databases are built ontop of a key-value storage engine of some nature. In our
case we are using (feb 2019) sqlite and hopefully SLED in the future.

So our entries that contain sets of avas, these are serialised into a byte format (feb 2019, json
but soon cbor) and stored in a table of "id: entry". For example:

    |----------------------------------------------------------------------------------------|
    |  ID  |                                     data                                        |
    |----------------------------------------------------------------------------------------|
    |  01  | { 'Entry': { 'name': ['name'], 'class': ['person'], 'uuid': ['...'] } }         |
    |  02  | { 'Entry': { 'name': ['beth'], 'class': ['person'], 'uuid': ['...'] } }         |
    |  03  | { 'Entry': { 'name': ['alan'], 'class': ['person'], 'uuid': ['...'] } }         |
    |  04  | { 'Entry': { 'name': ['john'], 'class': ['person'], 'uuid': ['...'] } }         |
    |  05  | { 'Entry': { 'name': ['kris'], 'class': ['person'], 'uuid': ['...'] } }         |
    |----------------------------------------------------------------------------------------|

The ID column is *private* to the backend implementation and is never revealed to the higher
level components. However the ID is very important to indexing :)

If we wanted to find Eq(name, john) here, what do we need to do? A full table scan is where we
perform:

    data = sqlite.do(SELECT * from id2entry);
    for row in data:
        entry = deserialise(row)
        entry.match_filter(...) // check Eq(name, john)

For a small database (maybe up to 20 objects), this is probably fine. But once you start to get
much larger this is really costly. We continually load, deserialise, check and free data that
is not relevant to the search. This is why full table scans of any database (sql, ldap, anything)
are so costly. It's really really scanning everything!

How does indexing work?
-----------------------

Indexing is a pre-computed lookup table of what you *might* search in a specific format. Let's say
in our example we have an equality index on "name" as an attribute. Now in our backend we define
an extra table called "index_eq_name". It's contents would look like:

    |------------------------------------------|
    |  index    | idl                          |
    |------------------------------------------|
    |  alan     | [03, ]                       |
    |  beth     | [02, ]                       |
    |  john     | [04, ]                       |
    |  kris     | [05, ]                       |
    |  name     | [01, ]                       |
    |------------------------------------------|

So when we perform our search for Eq(name, john) again, we see name is indexed. We then perform:

    SELECT * from index_eq_name where index=john;

This would give us the idl (ID list) of [04,]. This is the "ID's of every entry where name equals
john".

We can now take this back to our id2entry table and perform:

    data = sqlite.do(SELECT * from id2entry where ID = 04)

The key-value engine only gives us the entry for john, and we have a match! If id2entry had 1 million
entries, a full table scan would be 1 million loads and compares - with the index, it was 2 loads and
one compare. That's 30000x faster (potentially ;) )!

To improve on this, if we had a query like Or(Eq(name, john), Eq(name, kris)) we can use our
indexes to speed this up.

We would query index_eq_name again, and we would perform the search for both john, and kris. Because
this is an OR we then union the two idl's, and we would have:

    [04, 05,]

Now we just have to get entries 04,05 from id2entry, and we have our matching query. This means
filters are often applied as idl set operations.

Compressed ID lists
-------------------

In order to make idl loading faster, and the set operations faster there is an idl library
(developed by me, firstyear), which will be used for this. To read more see:

https://github.com/Firstyear/idlset

Filter Optimisation
-------------------

Filter optimisation begins to play an important role when we have indexes. If we indexed
something like "Pres(class)", then the idl for that search is the set of all database
entries. Similar, if our database of 1 million entries has 250,000 class=person, then
Eq(class, person), will have an idl containing 250,000 ids. Even with idl compression, this
is still a lot of data!

There tend to be two types of searches against a directory like kanidm.

* Broad searches
* Targetted single entry searches

For broad searches, filter optimising does little - we just have to load those large idls, and
use them. (Yes, loading the large idl and using it is still better than full table scan though!)

However, for targetted searches, filter optimisng really helps.

Imagine a query like:

    And(Eq(class, person), Eq(name, claire))

In this case with our database of 250,000 persons, our idl's would have:

    And( idl[250,000 ids], idl(1 id))

Which means the result will always be the *single* id in the idl or *no* value because it wasn't
present.

We add a single concept to the server called the "filter test threshold". This is the state in which
a candidate set that is not completed operation, is shortcut, and we then apply the filter in
the manner of a full table scan to the partial set because it will be faster than the index loading
and testing.

When we have this test threshold, there exists two possibilities for this filter.

    And( idl[250,000 ids], idl(1 id))

We load 250,000 idl and then perform the intersection with the idl of 1 value, and result in 1 or 0.

    And( idl(1 id), idl[250,000 ids])

We load the single idl value for name, and then as we are below the test-threshold we shortcut out
and apply the filter to entry ID 1 - yielding a match or no match.

Notice in the second, by promoting the "smaller" idl, we were able to save the work of the idl load
and intersection as our first equality of "name" was more targetted?

Filter optimisation is about re-arranging these filters in the server using our insight to
data to provide faster searches and avoid indexes that are costly unless they are needed.

In this case, we would *demote* any filter where Eq(class, ...) to the *end* of the And, because it
is highly likely to be less targetted than the other Eq types. Another example would be promotion
of Eq filters to the front of an And over a Sub term, wherh Sub indexes tend to be larger and have
longer IDLs.



