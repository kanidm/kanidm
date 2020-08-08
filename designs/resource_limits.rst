Resource Limits
---------------

As security sensitive software, kanidm must be "available" (as defined by
confidentiality, integrity, and availability). This means that as a service we must
be able to handle a large volume of potentially malicous traffic, and still able
to serve legitimate requests without fault or failure.

To achieve this, the resources of the server must be managed and distributed to allow
potentially thousands of operations per second, while preventing exhaustion of those
resources.

Kanidm is structured as a database, where each request requires a process
to resolve that query into an answer. This could be a request for authetication
which is a true/false response, or a request for an identity so that we can
determine their groups for authorisation, or even just a request to find
someone's email address in a corporate directory context.

Each operation requires resources to complete individually, but many operations
can be processed in parallel.

Resource exhaustion occurs when input from a client consumes more resources 
than the server can provide. This means the attack surface is any possible input
and how the server interprets and processes that input. In kanidm this could be
a search filter for example - the query may be small, but it could be expensive
to compute.

CPU time
========

Every operation requires time on a CPU. A CPU logically is many threads which
can have many processes in parallel, and each thread has a limit on how many
instructions it can perform per second. This makes CPU a finite resource for
our system.

This means that given a say 8 core CPU, each individual core may be able to
complete 1000 operations per second, and combined this becomes 8x1000.

If CPU time is exhausted, then operations are unable to be served. This means
that we must manage the amount of time an operation is allowed to take
on the system.

Some types of queries can take more time than others. For example:

* Unindexed searches which require full table scans.
* Indexed searches that have a large number of results.
* Write operations that affect many entries.

These necesitate the following limits:

* No unindexed searches allowed
* Prevent searching on terms that do not exist (done, filter schema validation)
* Limit on the number of entries that can be checked during a partial indexed search
* Limit on the number of entries that can be loaded from a fully indexed search
* Limit on the number of entries that can be written during a write operation
* Reduce the size of allowed queries to prevent complex index access patterns

Memory (RAM) Capacity
=====================

A system has finite amounts of RAM which must be shared between all CPUs of the system.
Effective use of that RAM improves the speed of all operations, meaning that as a shared
resource it can not be monopolised by a single operation.

Each operation can be assumed to have access to RAM/n CPUs of RAM. If an operation temporarily
exceeds this, the impact is minimal, but continued use of a single CPU using a high capacity
of RAM can prevent other operations functioning. Additionally, past operations can impact
the content of RAM though cache invalidation attacks.

To prevent overuse of RAM, the following must be considered

* Cache strategies to prevent invalidation attacks (done, ARC + ahash).
* Limit the amount of entries that can be dirtied in a write operation
* Limit the number of entries that can be filter-tested in partial index queries
* Limit the amount of entries that can be loaded for a read operation
* Limit the size of cache to allow room for operation result sets (done)
* Cache closer to the application rather than using db/vfs caches (done)
* Compress resources that consume bandwidth to operate on (done, index compression)

Disk IOPS
=========

Storage has a limit on how many input/output operations it can perform per second. Each operation
must be able to access the storage system for entries and indexes that may not be cached in memory.
The best way to reduce IOPS is more RAM to allow more application level caching, but this is
not always possible. This means that we must have operations minimise their IOPS requirements,
or to not issue or allow requests that would generate large amounts of IOPS.

* Cache strategies that keep cache hit ratios high (done, ARC)
* Compress elements to reduce IOPS for transfer to RAM (done indexes, not-done entries)
* Limit the number of large items that can be loaded in an operation IE partial index scans, full table scans
* Limit the size of write operations.

Disk Capacity
=============

If the storage capacity is exceeded this can cause the system to panic or stop, which would act
as a denial of service. It may also prevent security auditing or other data to be recorded or in
the worst case, data corruption. This means that during write operations, the amount of change
must be limited.

* Limit the number of entries that can be dirtied in an operation
* Limit the maximum number of multivalue attributes on an entry to prevent the entry growing over-size
* Entry maximum size limits
* Limit the amount of churn in an entry to prevent excessive changelog growth

Stack Limits
============

As some operations are recursive, the stack depth becomes a concern because when the stack depth is exceeded, the system
can crash or panic. The major recursive structure is filters and how we process queries.

To prevent stack exhaustion:

* Limit the depth of nesting in a search query (filter).

Network
=======

To prevent a client from exhausting memory, but also network bandwidth, if an operation is too
large it should be denied

* Limit size of incoming network requests

Limits Summary
==============

This summary is the set of limits that should be applied. Note some limits prevent multiple issues,
and the limits apply in different areas.

Search Limits:
* Prevent searching on terms that do not exist (done, filter schema validation)
* Deny unindexed searches
* Limit the amount of entries that can be loaded for a read operation
* Limit the number of entries that can be filter-tested in partial index queries
* Limit on the number of entries that can be loaded from a search
* Limit the depth of nesting in a search query (filter).
* Reduce the size of allowed queries to prevent complex index access patterns

Caching:
* Cache strategies to prevent invalidation attacks (done, ARC + ahash).
* Limit the size of cache to allow room for operation result sets (done)
* Cache closer to the application rather than using db/vfs caches (done)

Network:
* Limit size of incoming network requests

Db storage:
* Compress elements to reduce IOPS for transfer to RAM (done indexes, not-done entries)

Writes:
* Limit the number of entries that can be dirtied in an operation
* Limit the maximum number of multivalue attributes on an entry to prevent the entry growing over-size
* Entry maximum size limits
* Limit the amount of churn in an entry to prevent excessive changelog growth

These limits should be applied per-account to allow some accounts to override these, for example
an application which needs to bulk update accounts, or admins who need to perform audits.

The system maintains a default set of limits. Accounts can then have resource groups associated.
The "highest" value of the resource group or default is the value that is applied. These limits
could also be claim based or related, meaning they become per session rather than per account, so
they would be stored in the user authentication token.

The session limits would be:

* allow unindexed search
* maximum number of entries in search
* maximum number of entries in partial filter test
* number of filter elements
* maximum number of modified entries
* write rate limit (writes over time)
* network request size

The system limits that can not be account overridden are:

* maximum entry size
* maximum number of multi value attributes

