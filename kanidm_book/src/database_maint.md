# Database Maintenance

## Reindexing

In some (rare) cases you may need to reindex. Please note the server will sometimes reindex on
startup as a result of the project changing its internal schema definitions. This is normal and
expected - you may never need to start a reindex yourself as a result!

You'll likely notice a need to reindex if you add indexes to schema and you see a message in your
logs such as:

```
Index EQUALITY name not found
Index {type} {attribute} not found
```

This indicates that an index of type equality has been added for name, but the indexing process has
not been run. The server will continue to operate and the query execution code will correctly
process the query - however it will not be the optimal method of delivering the results as we need
to disregard this part of the query and act as though it's un-indexed.

Reindexing will resolve this by forcing all indexes to be recreated based on their schema
definitions (this works even though the schema is in the same database!)

```bash
docker stop <container name>
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd reindex -c /data/server.toml
docker start <container name>
```

Generally, reindexing is a rare action and should not normally be required.

## Vacuum

Vacuuming is the process of reclaiming un-used pages from
the database freelists, as well as performing some data reordering tasks that may make some queries
more efficient. It is recommended that you vacuum after a reindex is performed or when you wish to
reclaim space in the database file.

Vacuum is also able to change the pagesize of the database. After changing `db_fs_type` (which
affects pagesize) in server.toml, you must run a vacuum for this to take effect:

```bash
docker stop <container name>
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd vacuum -c /data/server.toml
docker start <container name>
```

## Verification

The server ships with a number of verification utilities to ensure that data is consistent such as
referential integrity or memberof.

Note that verification really is a last resort - the server does _a lot_ to prevent and self-heal
from errors at run time, so you should rarely if ever require this utility. This utility was
developed to guarantee consistency during development!

You can run a verification with:

```bash
docker stop <container name>
docker run --rm -i -t -v kanidmd:/data \
    kanidm/server:latest /sbin/kanidmd verify -c /data/server.toml
docker start <container name>
```

If you have errors, please contact the project to help support you to resolve these.
