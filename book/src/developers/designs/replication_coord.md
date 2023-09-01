# Replication Coordinator Design

Many other IDM systems configure replication on each node of the topology. This means that the
administrator is responsible for ensuring all nodes are connected properly, and that agreements are
bidirectional. As well this requires manual work for administrators to configure each node
individually, as well as monitoring individually. This adds a significant barrier to "stateless"
configurations.

In Kanidm we want to avoid this - we want replication to be coordinated to make deployment of
replicas as easy as possible for new sites.

## Kanidm Replication Coordinator

The intent of the replication coordinator (KRC) is to allow nodes to subscribe to the KRC which
configures the state of replication across the topology.

```
1. Out of band -                ┌────────────────┐
 issue KRC ca + ────────────────┤                │
   Client JWT.                  │                │
        │       ┌──────────────▶│                │──────────────────────┐
        │       │2. HTTPS       │     Kanidm     │                      │
        │     JWT in Bearer     │  Replication   │            5. Issue repl config
        │  Request repl config  │  Coordinator   │             with partner public
        │  Send self signed ID  │                │                     key
        │       │  cert         │                │                      │
        │       │     ┌─────────│                │◀────────┐            │
        │       │     │         │                │       4. HTTPS       │
        │       │     │         └────────────────┘    JWT in Bearer     │
        │       │   3. Issue                       Request repl config  │
        │       │  repl config                     Send self signed ID  │
        │       │     │                                    cert         │
        │       │     │                                    │            │
        │       │     │                                    │            │
        │       │     │                                    │            │
        │       │     │                                    │            │
        ▼       │     ▼                                    │            ▼
       ┌────────────────┐                                ┌─┴──────────────┐
       │                │                                │                │
       │                │                                │                │
       │                │       5. mTLS with self        │                │
       │                │──────────signed cert──────────▶│                │
       │ Kanidm Server  │      Perform replication       │ Kanidm Server  │
       │     (node)     │                                │     (node)     │
       │                │                                │                │
       │                │                                │                │
       │                │                                │                │
       │                │                                │                │
       └────────────────┘                                └────────────────┘
```

The KRC issues configuration tokens. These are JWT's that are signed by the KRC.

A configuration token is _not_ unique to a node. It can be copied between many nodes. This allows
stateless deployments where nodes can be spun up and provided their replication config.

The node is provided with the KRC TLS CA, and a configuration token.

The node when configured contacts the KRC with it's configuration token as bearer authentication.
The KRC uses this to determine and issue a replication configuration. Because the configuration
token is signed by the KRC, a fraudulent configuration token can _not_ be used by an attacker to
fraudulently subscribe a kanidm node. Because the KRC is contacted over TLS this gives the node
strong assurances of the legitimacy of the KRC due to TLS certificate validation and pinning.

The KRC must be able to revoke replication configuration tokens in case of a token disclosure.

The node sends it's KRC, server UUID, and server repl public key to the KRC.

The configuration token defines the replication group identifier of that node. The KRC uses the
configuration token _and_ the servers UUID to assign replication metadata to the node. The KRC
issues a replication configuration to the node.

The replication configuration defines the nodes that the server should connect to, as well as
providing the public keys that are required for that node to perform replication. These are
elaborated on in node configuration.

## Kanidm Node Configuration

There are some limited cases where an administrator may wish to _manually_ define replication
configuration for their deployments. In these cases the admin can manually configure replication
parameters in the Kanidm configuration.

A kanidm node for replication requires either:

- The URL to the KRC
- the KRC CA cert
- KRC issued configuration JWT

OR

- A replication configuration map

A replication configuration map contains a set of agreements and their direction of operation.

All replicas require:

- The direct url that other nodes can reach them on (this is NOT the origin of the server!)

### Pull mode

This is the standard and preferred mode. The map contains for each node to pull from.

- the url of the node's replication endpoint.
- The self-signed node certificate to be pinned for the connection.
- If a refresh required message is received, if automatic refresh should be carried out.

### Push mode

This mode is only available in manual configurations, and should only be used as a last resort.

- The url of the nodes replication endpoint.
- The self-signed node certificate to be pinned for the connection.
- If a refresh required message would be sent, if the node should be force-refreshed next cycle.

## Worked examples

### Manual configuration

There are two nodes, A and B.

The administrator configures the kanidm server with replication urls

[replication] node\_url = https://private.name.of.node

The administrator extracts their replication certificates with the kanidmd binary admin features.
This will reflect the node\_url in the certificate.

kanidmd replication get-certificate

For each node, a replication configuration is created in json. For A pulling from B.

```
[
  { "pull":
    {
      url: "https://node-b.private-name",
      publiccert: "pem certificate from B",
      automatic\_refresh: false
    }
  },
  { "allow-pull":
    {
      clientcert: "pem certificate from B"
    }
  }
]
```

For B pulling from A.

```
[
  { "pull":
    {
      url: "https://node-a.private-name",
      publiccert: "pem certificate from A",
      automatic\_refresh: false
    }
  },
  { "allow-pull":
    {
      clientcert: "pem certificate from A"
    }
  }
]
```

Notice that automatic refresh only goes from A -> B and not the other way around. This allows one
server to be "authoritative".

### KRC Configuration

> Still not fully sure about the KRC config yet. More thinking needed!

The KRC is configured with it's URL and certificates.

[krc\_config] origin = https://krc.example.com tls\_chain = /path/to/tls/chain tls\_key =
/path/to/tls/key

The KRC is also configured with replication groups.

```
  [origin\_nodes]
  # This group never auto refreshes - they are authoritative.
  mesh = full

  [replicas\_syd]
  # Every node has two links inside of this group.
  mesh = 2
  # at least 2 nodes in this group link externally.
  linkcount = 2
  linkto = [ "origin\_nodes" ]

  [replicas\_bne]
  # Every node has one link inside of this group.
  mesh = 1
  # at least 1 node in this group link externally.
  linkcount = 1
  linkto = [ "origin\_nodes" ]
```

This would yield the following arrangement.

```
                      ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                        origin_nodes                       │
                      │
                          ┌────────┐         ┌────────┐    │
                      │   │        │         │        │
                          │   O1   │◀───────▶│   O2   │    │
                      │   │        │         │        │
                          └────────┘◀───┬───▶└────────┘    │
                      │        ▲        │         ▲
                               │        │         │        │
                      │        │        │         │
                               ▼        │         ▼        │
                      │   ┌────────┐◀───┴───▶┌────────┐
                          │        │         │        │    │
                      │   │   O3   │◀───────▶│   O4   │◀─────────────────────────────┐
                          │        │         │        │    │                         │
                      │   └────────┘         └────────┘                              │
                               ▲                  ▲        │                         │
                      └ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─                          │
                               │                  │                                  │
                               │                  │                                  │
                               │                  │                                  │
                            ┌──┘                  │                                  │
                            │                     │                                  │
                            │                     │                                  │
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─             │      ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─
  replicas_bne              │        │            │        replicas_syd              │        │
│                           │                     │      │                           │
    ┌────────┐         ┌────────┐    │            │          ┌────────┐         ┌────────┐    │
│   │        │         │        │                 │      │   │        │         │        │
    │   B1   │◀───────▶│   B2   │    │            └──────────│   S1   │◀───────▶│   S2   │    │
│   │        │         │        │                        │   │        │         │        │
    └────────┘         └────────┘    │                       └────────┘         └────────┘    │
│                           ▲                            │        ▲                  ▲
                            │        │                            │                  │        │
│                           │                            │        │                  │
                            ▼        │                            ▼                  ▼        │
│   ┌────────┐         ┌────────┐                        │   ┌────────┐         ┌────────┐
    │        │         │        │    │                       │        │         │        │    │
│   │   B3   │◀───────▶│   B4   │                        │   │   S3   │◀───────▶│   S4   │
    │        │         │        │    │                       │        │         │        │    │
│   └────────┘         └────────┘                        │   └────────┘         └────────┘
                                     │                                                        │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                    └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
```

!!! TBD - How to remove / decomission nodes?

I think origin nodes are persistent and must be manually defined. Will this require configuration of
their server uuid in the config?

Auto-node groups need to check in with periodic elements, and missed checkins.

Checkins need to send ruv?

If a node misses checkins after a certain period they should be removed from the KRC knowledge?

Should replication maps have "priorities" to make it a tree so that if nodes are offline then it can
auto-re-route? Should they have multiple paths? Want to avoid loops.

Or is delete of nodes a manual cleanup / triggers clean-ruv?

I think some more thought is needed here. Possibly a node state machine.

### Requirements

- Cryptographic (key) only authentication
- Node to Node specific authentication
- Scheduling of replication
- Multiple nodes
- Direction of traffic?
- Use of self-signed issued certs for nodes.
- Nodes must reject if incoming clients have the same certs.
