Logging Design (Refactor)
-------------------------

Logging is how the server communicates to developers and administrators about the state
of the service, and how operations are performing and what they are doing. It's important
this is clear in how it communicates. Today (2020-05-12) the log has been written with
development in mind, and has a structure that has as a result, become hard to parse and
understand. This has motivated a rewrite of logging to improve how the servers state
and errors are communicated to users.

Use Cases
---------

* Developer Bug Reports

A developer should be able to see the internal state of the server, and why any decision
or logic path was taken, so that errors or logic can be analysed post-incident. The
information in the log and the source code should be enough to resolve any issues, as we
may not have LLDB access to any consumers site, or any effective reproducer.

* Security Audits

We must be able to see why any security decision was made, such as credential validation,
access control application, or group/claim issuing to a session. This should be connected
to the IP and other identifiers of the caller.

* Error Analysis

For an administrator, they must be able to determine why an operation is failing in detail
so they can advise on how a consumer or user could change their behaviour to improve the
situation (beyond the error messages we return).

* Performance

Administrators and Developers should be able to analyse fine grained information about the
performance of any operation, and make informed decisions about tuning (such as caches or
or threads), and developers should be able to identify code paths that are under pressure
and could be targets for improvement.

* Containers

Logs should be access via an API, and support some querying or extraction that can be
provided to other services. It should also be sent on stdout/err for other systems to look at.

Details
-------

As developers we should indicate what messages are relevant to what use case as part of the
message. Log levels are used in other services, but that allows messages to be missed. Instead
we log every "service" always, but filter them to different locations.

This leads to the following log categories:

* Analysis
    * Display of all logic branches and why decision points or paths taken
    * A unique event ID that associates related log messages
* Performance
    * Cache and DB metrics available
    * Performance frames of timing of key points
    * Structure of the performance frames to understand the execution paths taken.
    * Display of query optimisation
    * Display of query planning and application
* Failure (server failure)
    * Hard Errors
* Warning (admin should take action)
    * Possible misconfiguration
* OperationError (user mistake, op mistake etc)
    * All error reports and finalised result summaries logged
    * The unique event ID is provided in any operation success or failure.
* Security (aka audit)
    * Filtering of security sensitive attributes (via debug/display features)
    * Display of sufficent information to establish a security picture of connected actions via the user's uuid/session id.
    * Tracking of who-changed-what-when-why
* Replication
    * TODO

It can be seen pretty quickly that multiple message types are useful across categories. For
example, the unique event id for all messages, how hard errors affect operation errors
or how an operation error can come from a security denial.

Logging must also remain a seperate thread and async for performance.

This means that the best way to declare these logs is a unified log which can be filtered based
on the admins or consumers needs.

API
---

For all types, it's important that we can associate all related events correctly. When the
operation initiates we assign an event-id that is part of the audit trail.

Statistics
==========

Stats should be accumulated in a statistics variable so that we can determine possible
tuning and other events related. Useful stats would be:

* Cache Hits
* Cache Misses
* Cache Inclusions

* Number of Searches
* Number of Entries Modified

This would be then logged as a structured line such as:

    { 'entry_cache_miss': 8, 'idl_cache_miss': 8, 'entry_cache_hit': 16', .... }

This would also then be fed back to the global stats thread for averaging.

Performance
===========

The key metric for performance is time-in-function so it would be good to be able to
build a value like:

        {
            'name': 'do_search',
            'time': x,
            'pct': 100,
            called: [
                {
                    'name': 'filter2idl',
                    'time': x',
                    called: [],
                },
                {
                    ...
                }
            ]
        }

This would allow a rich view of how much time went to any function at a high level, as then
further investigation can occur.

Query Analysis
==============

To analyse a query we need:

* The original query
* The optimised version, with index tagging/profiling choices.
* The idl's that were loaded and how the query was applied
* The idl of the final result set.

Security Events
===============

* What access controls were considered?
* Who authenticated and where from?
* Audit of who modified what when why.

Analysis
========

This is generally what is "debug" logging, which is just decision points and verbose
descriptions of what we went where.

Admin Notification
==================

This is warnings or errors that the admin should be aware of.

User Events
===========

This must associate what happened for a user



