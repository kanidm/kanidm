# Frequently Asked Questions

... or ones we think people _might_ ask.

## Why TLS?

You may have noticed that Kanidm requires you to configure TLS in your container or server install.

We are a secure-by-design rather than secure-by-configuration system, so TLS for all connections is
considered mandatory and a default rather than an optional feature you add later.

### Why disallow HTTP (without TLS) between my load balancer and Kanidm?

Because Kanidm is one of the keys to a secure network, and insecure connections to them are not best
practice. This can allow account hijacking, privilege escalation, credential disclosures, personal
information leaks and more.

### What are Secure Cookies?

`secure-cookies` is a flag set in cookies that asks a client to transmit them back to the origin
site if and only if the client sees HTTPS is present in the URL.

Certificate authority (CA) verification is _not_ checked - you can use invalid, out of date
certificates, or even certificates where the `subjectAltName` does not match, but the client must
see https:// as the destination else it _will not_ send the cookies.

### How Does That Affect Kanidm?

Kanidm's authentication system is a stepped challenge response design, where you initially request
an "intent" to authenticate. Once you establish this intent, the server sets up a session-id into a
cookie, and informs the client of what authentication methods can proceed.

If you do NOT have a HTTPS URL, the cookie with the session-id is not transmitted. The server
detects this as an invalid-state request in the authentication design, and immediately breaks the
connection, because it appears insecure. This prevents credential disclosure since the
authentication session was not able to be established due to the lost session-id cookie.

Simply put, we are trying to use settings like `secure_cookies` to add constraints to the server so
that you _must_ perform and adhere to best practices - such as having TLS present on your
communication channels.

## Can I change the database backend from SQLite to - name of favourite database here -

No, it is not possible swap out the SQLite database for any other type of SQL server.

_ATTEMPTING THIS WILL BREAK YOUR KANIDM INSTANCE IRREPARABLY_

This question is normally asked because people want to setup multiple Kanidm servers connected to a
single database.

Kanidm does not use SQL as a _database_. Kanidm uses SQL as a durable key-value store and Kanidm
implements it's own database, caching, querying, optimisation and indexing ontop of that key-value
store.

As a result, because Kanidm specifically implements it's own cache layer above the key-value store
(sqlite in this example) then if you were to connect two Kanidm instances to the same key-value
store, as each server has it's own cache layer and they are not in contact, it is possible for
writes on one server to never be observed by the second, and if the second were to then write over
those entries it will cause loss of the changes from the first server.

## Why so many crabs?

It's [a rust thing](https://rustacean.net).

## Will you implement -insert protocol here-

Probably, on an infinite time-scale! As long as it's not STARTTLS. Please log an issue and start the
discussion!

## Why do the crabs have knives?

Don't [ask](https://www.youtube.com/watch?v=0QaAKi0NFkA). They just
[do](https://www.youtube.com/shorts/WizH5ae9ozw).

## Why won't you take this FAQ thing seriously?

Look, people just haven't asked many questions yet.
