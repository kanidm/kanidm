# Replication Coordinator

Many other IDM systems configure replication on each node of the topology. This means that the administrator is
responsible for ensuring all nodes are connected properly, and that agreements are bidirectional. As well this requires
manual work for administrators to configure each node individually, as well as monitoring individually. This adds a
significant barrier to "stateless" configurations.

In Kanidm we want to avoid this - we want replication to be coordinated to make deployment of replicas as easy as
possible for new sites.

## Kanidm Replication Coordinator

The intent of the replication coordinator (KRC) is to allow nodes to subscribe to the KRC which configures the state of
replication across the topology.

```text
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

## Kanidm Node Configuration

There are some limited cases where an administrator may wish to _manually_ define replication configuration for their
deployments. In these cases the admin can manually configure replication parameters in the Kanidm configuration.

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

This is the standard mode. The map contains for each node to pull replication data from. This logically maps to the
implementation of the underlying replication mechanism.

- the url of the node's replication endpoint.
- The self-signed node certificate to be pinned for the connection.
- If a refresh required message is received, if automatic refresh should be carried out.

### Push mode

This mode is unlikely to be developed as it does not match the way that replication works.

## Worked examples

### Manual configuration

There are two nodes, A and B.

The administrator configures both kanidm servers with replication urls.

```toml
# Server A
[replication]
origin = "repl://kanidmd_a:8444"
bindaddress = "[::]:8444"
```

```toml
# Server B
[replication]
origin = "repl://kanidmd_b:8444"
bindaddress = "[::]:8444"
```

The administrator extracts their replication certificates with the kanidmd binary admin features. This will reflect the
`node_url` in the certificate.

```shell
kanidmd replication get-certificate
```

For each node, a replication configuration is created in json.

For A pulling from B.

```toml
[replication."repl://kanidmd_b:8444"]
type = "mutual-pull"
partner_cert = "M..."
automatic_refresh = false
```

For B pulling from A.

```toml
[replication."repl://kanidmd_a:8444"]
type = "mutual-pull"
partner_cert = "M..."
automatic_refresh = true
```

Notice that automatic refresh only goes from A -> B and not the other way around. This allows one server to be
"authoritative".

### KRC Configuration

The KRC is enabled as a replication parameter. This informs the node that it must not contact other nodes for its
replication topology, and it prepares the node for serving that replication metadata. This is analogous to a single node
operation configuration.

```toml
[replication]
origin = "repl://kanidmd_a:8444"
bindaddress = "[::]:8444"

krc_enable = true

# krc_url -- unset
# krc_ca_dir -- unset
```

All other nodes will have a configuration of:

```toml
[replication]
origin = "repl://kanidmd_b:8444"
bindaddress = "[::]:8444"

# krc_enable -- unset / false

# krc_url = https://private.name.of.krc.node
krc_url = https://kanidmd_a
# must contain ca that signs kanidmd_a's tls_chain.
krc_ca_dir = /path/to/ca_dir
```

The domain will automatically add a `Default Site`. The KRC implies its own membership to "Default Site" and it will
internally add itself to the `Default Site`.

The KRC can then issue Tokens that define which Site a new replica should join. Initially we will only allow
`Default Site` (and will disallow creation of other sites).

The new replica will load its KRC token from the environment variable `KANIDMD_KRC_TOKEN_PATH`. This value will contain
a file path where the JWT is stored. This is compatible with systemd credentials and docker secrets. By default the
value if unset will be defined by a profile default (`/etc/kanidm/krc.token` or `/data/krc.token`).

A new replica can then contact the `krc_url` validating the presented TLS chain with the roots from `krc_ca_dir` to
assert the legitimacy of the KRC. Only once these are asserted, then the KRC token can be sent to the instance as a
`Bearer` token. The new replica will also provide its mTLS certificate and its server UUID.

Once validated, the KRC will create or update the server's replica entry. The replica entry in the database will contain
the active mTLS cert of the replica and a reference to the replication site that the token referenced.

This will additionally add the "time first seen" to the server entry.

From this, for each server in the replication site associated to the token, the KRC will provide a replication config
map to the new replica providing all URL's and mTLS certs.

Anytime the replica checks in, if the KRC replication map has changed a new one will be provided, or the response will
be `None` for no changes.

To determine no changes we use a "generation". This is where any change to a replication site or server entries will
increment the generation counter. This allows us to detect when a client requires a new configuration or not.

If a server's entry in the database is marked to be `Revoked` then it will remain in the database, but be ineligible for
replication participation. This is to allow for forced removal of a potentially compromised node.

The KRC will periodically examine its RUV. For any server entry whose UUID is not contained in the RUV, and whose "time
first seen + time window" is less than now, then the server entry will be REMOVED for inactivity since it has now been
trimmed from the RUV.

### Moving the Replication Coordinator Role

Since the coordinator is part of a kanidmd server, there must be a process to move the KRC to another node.

Imagine the following example. Here, Node A is acting as the KRC.

```text
┌─────────────────┐                ┌─────────────────┐
│                 │                │                 │
│                 │                │                 │
│     Node A      │◀───────────────│     Node B      │
│                 │                │                 │
│                 │                │                 │
└─────────────────┘                └─────────────────┘
         ▲     ▲
         │     │
         │     │
         │     └────────────────────────────┐
         │                                  │
         │                                  │
         │                                  │
┌─────────────────┐                ┌─────────────────┐
│                 │                │                 │
│                 │                │                 │
│     Node C      │                │     Node D      │
│                 │                │                 │
│                 │                │                 │
└─────────────────┘                └─────────────────┘
```

This would allow Node A to be aware of B, C, D and then create a full mesh.

We wish to decommission Node A and promote Node B to become the new KRC. Imagine at this point we cut over Node D to
point its KRC at Node B.

```text
┌─────────────────┐                ┌─────────────────┐
│                 │                │                 │
│                 │                │                 │
│     Node A      │                │     Node B      │
│                 │                │                 │
│                 │                │                 │
└─────────────────┘                └─────────────────┘
         ▲                                  ▲
         │                                  │
         │                                  │
         │                                  │
         │                                  │
         │                                  │
         │                                  │
┌─────────────────┐                ┌─────────────────┐
│                 │                │                 │
│                 │                │                 │
│     Node C      │                │     Node D      │
│                 │                │                 │
│                 │                │                 │
└─────────────────┘                └─────────────────┘
```

Since we still have the Server Entry records in the Default Site on both Node A and Node B, then all nodes will continue
to participate in full mesh, and will update certificates as required.

Since all servers would still be updating their RUV's and by proxy, updating RUV's to their partners then no nodes will
be trimmed from the topology.

This allows a time window where servers can be moved from Node A to Node B.

### Gruesome Details

Server Start Up Process

```text
Token is read from a file defined in the env - this works with systemd + docker secrets

Token is JWT with HS256. (OR JWE + AES-GCM)

Read the token
- if token domain_uuid != our domain_uuid -> set status to "waiting"
    - empty replication config map
- if token domain_uuid == domain_uuid -> status to "ok"
    - use cached replication config map

No TOKEN -> Implies KRC role.
- Set status to "ok", we are the domain_uuid source.
```

Client Process

- Connect to KRC
  - Provide token for site binding
  - Submit my server_uuid
  - Submit my public cert with the request
  - Submit current domain_uuid + generation if possible

- Reply from KRC -> repl config map.
  - Config_map contains issuing KRC server uuid.
  - If config_map generation > current config_map
    - Reload config.
  - If config_map == None
    - Current map remains valid.

KRC Process

- Validate Token
- Is server_uuid present as a server entry?
  - If no: add it with site association
  - If yes: verify site associated to token
- Is server_uuid certificate the same as before?
  - If no: replace it.
- Compare domain_uuid + generation
  - If different supply config
  - Else None (no change)

### FUTURE: Possible Read Only nodes

For R/O nodes, we need to define how R/W will pass through. I can see a possibility like

```text
                                No direct line
       ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ of sight─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

       │                                                               ▼
┌────────────┐                 ┌─────────────┐────OOB Write────▶┌─────────────┐
│            │                 │ Remote Kani │                  │             │
│   Client   │─────Write──────▶│   Server    │                  │    Main     │
│            │                 │             │                  │             │
└────────────┘                 └─────────────┘◀───Replication───└─────────────┘
```

This could potentially even have some filtering rules about what's allowed to proxy writes through. Generally though I
think that RO will need a lot more thought, for now I want to focus on just simple cases like a pair / group of four
replicas. 😅

### Requirements

- Cryptographic (key) only authentication
- Node to Node specific authentication
- Scheduling of replication
- Multiple nodes
- Direction of traffic?
- Use of self-signed issued certs for nodes.
- Nodes must reject if incoming clients have the same certs.
