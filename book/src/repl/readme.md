# Replication

## Introduction

Replication allows two or more Kanidm servers to exchange their databases and keep their content synchronised. This is
critical to allow multiple servers to act in failover groups for highly available infrastructure.

Kanidm replication is eventually consistent. This means that there are no elections or quorums required between nodes -
all nodes can accept writes and distribute them to all other nodes. This is important for security and performance.

Because replication is eventually consistent, this means that there can be small delays between different servers
receiving a change. This may result in some users noticing discrepancies that are quickly resolved.

To minimise this, it's recommended that when you operate replication in a highly available deployment that you have a
load balancer that uses sticky sessions so that users are redirected to the same server unless a failover event occurs.
This will help to minimise discrepancies. Alternately you can treat replication and "active-passive" and have your load
balancer failover between the two nodes. Since replication is eventually consistent, there is no need for a failover or
failback procedure.

In this chapter we will cover the details of planning, deploying and maintaining replication between Kanidm servers.

## Vocabulary

Replication requires us to use introduce specific words so that we can describe the replication environment.

### Change

An update made in the database.

### Node

A server that is participating in replication.

### Pull

The act of requesting data from a remote server.

### Push

The act of supplying data to a remote server.

### Node Configuration

A descriptor that allows a node to pull from another node.

### Converge

To approach the same database state.

### Topology

The collection of servers that are joined in replication and converge on the same database content. The topology is
defined by the set of node configurations.

### Replication

The act of exchanging data from one node to another.

### Supplier

The node that is supplying data to another node.

### Consumer

The node that is receiving content from a supplier.

### Refresh

Deleting all of a consumer's database content, and replacing it with the content of a supplier.

### Incremental Replication

When a supplier provides a "differential" between the state of the consumer and the supplier for the consumer to apply,
coverging toward the same database state.

### Conflict

If a consumer can not validate a change that a supplier provided, then the entry may move to a conflict state. All nodes
will converge to the same conflict state over time.

### Tombstone

A marker entry that displays an entry has been deleted. This allow all servers to converge and delete the data.
