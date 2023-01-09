## Frequently Asked Questions

This is a list of common questions that are generally raised by developers or technical users.

## Why don't you use library/project X?

A critical aspect of kanidm is the ability to test it. Generally requests to add libraries or
projects can come in different forms so I'll answer to a few of them:

## Is the library in Rust?

If it's not in Rust, it's not ellegible for inclusion. There is a single exception today (rlm
python) but it's very likely this will also be removed in the future. Keeping a single language
helps with testing, but also makes the project more accesible and consistent to developers.
Additionally, features exist in Rust that help to improve quality of the project from development to
production.

## Is the project going to create a microservice like architecture?

If the project (such as an external OAuth/OIDC gateway, or a different DB layer) would be used in a
tight-knit manner to Kanidm then it is no longer a microservice, but a monolith with multiple moving
parts. This creates production fragility and issues such as:

- Differences and difficulties in correlating log events
- Design choices of the project not being compatible with Kanidm's model
- Extra requirements for testing/production configuration

This last point is key. It is a critical part of kanidm that the following must work on all
machines, and run every single test in the suite.

```
git clone https://github.com/kanidm/kanidm.git
cd kanidm
cargo test
```

Not only this, but it's very important for quality that running `cargo test` truly tests the entire
stack of the application - from the database, all the way to the client utilities and other daemons
communicating to a real server. Many developer choices have already been made to ensure that testing
is the most important aspect of the project to ensure that every feature is high quality and
reliable.

Additon of extra projects or dependencies, would violate this principle and lead to a situation
where it would not be possible to effectively test for all developers.

## Why don't you use Raft/Etcd/MongoDB/Other to solve replication?

There are a number of reasons why these are generally not compatible. Generally these databases or
technolgies do solve problems, but they are not the problems in Kanidm.

## CAP theorem

CAP theorem states that in a database you must choose only two of the three possible elements:

- Consistency - All servers in a topology see the same data at all times
- Availability - All servers in a a topology can accept write operations at all times
- Partitioning - In the case of a network separation in the topology, all systems can continue to
  process read operations

Many protocols like Raft or Etcd are databases that provide PC guarantees. They guarantee that they
are always consistent, and can always be read in the face of patitioning, but to accept a write,
they must not be experiencing a partitioning event. Generally this is achieved by the fact that
these systems elect a single node to process all operations, and then re-elect a new node in the
case of partitioning events. The elections will fail if a quorum is not met disallowing writes
throughout the topology.

This doesn't work for Authentication systems, and global scale databases. As you introduce
non-negligible network latency, the processing of write operations will decrease in these systems.
This is why Google's Spanner is a PA system.

PA systems are also considered to be "eventually consistent". All nodes can provide reads and writes
at all times, but during a network partitioning or after a write there is a delay for all nodes to
arrive at a consistent database state. A key element is that the nodes perform an consistency
operation that uses application aware rules to allow all servers to arrive at the same state
_without_ communication between the nodes.

## Update Resolutionn

Many databases do exist that are PA, such as CouchDB or MongoDB. However, they often do not have the
properties required in update resolution that is required for Kanidm.

An example of this is that CouchDB uses object-level resolution. This means that if two servers
update the same entry the "latest write wins". An example of where this won't work for Kanidm is if
one server locks the account as an admin is revoking the access of an account, but another account
updates the username. If the username update happenned second, the lock event would be lost creating
a security risk. There are certainly cases where this resolution method is valid, but Kanidm is not
one.

Another example is MongoDB. While it does attribute level resolution, it does this without the
application awareness of Kanidm. For example, in Kanidm if we have an account lock based on time, we
can select the latest time value to over-write the following, or we could have a counter that can
correctly increment/advance between the servers. However, Mongo is not aware of these rules, and it
would not be able to give the experience we desire. Mongo is a very good database, it's just not the
right choice for Kanidm.

Additionally, it's worth noting that most of these other database would violate the previous desires
to keep the language as Rust and may require external configuration or daemons which may not be
possible to test.

## How PAM/nsswitch Work

Linux and BSD clients can resolve identities from Kanidm into accounts via PAM and nsswitch.

Name Service Switch (NSS) is used for connecting the computers with different data sources to
resolve name-service information. By adding the nsswitch libraries to /etc/nsswitch.conf, we are
telling NSS to lookup password info and group identities in Kanidm:

```
passwd: compat kanidm
group: compat kanidm
```

When a service like sudo, sshd, su etc. wants to authenticate someone, it opens the pam.d config of
that service, then performs authentication according to the modules defined in the pam.d config. For
example, if you run `ls -al /etc/pam.d /usr/etc/pam.d` in SUSE, you can see the services and their
respective pam.d config.
