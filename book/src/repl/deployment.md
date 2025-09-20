# Deployment

## Node Setup

On the servers that you wish to participate in the replication topology, you must enable replication in their
server.toml to allow identity certificates to be generated.

```toml
# server.toml

[replication]
# The hostname and port of the server that other nodes will connect to.
origin = "repl://localhost:8444"
# The bind address of the replication port.
bindaddress = "127.0.0.1:8444"
```

Once configured, deploy this config to your servers and restart the nodes.

## Manual Node Configurations

> [!NOTE]
>
> In the future we will develop a replication coordinator so that you don't have to manually configure this. But for
> now, if you want replication, you have to do it the hard way.

Each node has an identify certificate that is internally generated and used to communicate with other nodes in the
topology. This certificate is also used by other nodes to validate this node.

Let's assume we have two servers - A and B. We want B to consume (pull) data from A initially as A is our "first
server".

First display the identity certificate of A.

```bash
# Server A
docker exec -i -t <container name> \
  kanidmd show-replication-certificate
# certificate: "MII....."
```

Now on node B, configure the replication node config.

```toml
[replication]
# ...

[replication."repl://origin_of_A:port"]
type = "mutual-pull"
partner_cert = "MII... <as output from A show-replication-cert>"
```

Now we must configure A to pull from B.

```bash
# Server B
docker exec -i -t <container name> \
  kanidmd show-replication-certificate
# certificate: "MII....."
```

Now on node A, configure the replication node config.

```toml
[replication]
# ...

[replication."repl://origin_of_B:port"]
type = "mutual-pull"
partner_cert = "MII... <as output from B show-replication-cert>"
```

Then restart both servers. Initially the servers will refuse to synchronise as their databases do not have matching
`domain_uuids`. To resolve this you can instruct B to manually refresh from A with:

```bash
# Server B
docker exec -i -t <container name> \
  kanidmd refresh-replication-consumer
```

## Partially Automated Node Configurations

> [!NOTE]
>
> In the future we will develop a replication coordinator so that you don't have to manually configure this. But for
> now, if you want replication, you have to do it the hard way.

This is the same as the manual process, but a single server is defined as the "primary" and the partner server is the
"secondary". This means that if database issues occur the content of the primary will take precedence over the
secondary. For our example we will define A as the primary and B as the secondary.

First display the identity certificate

```bash
# Server A
docker exec -i -t <container name> \
  kanidmd show-replication-certificate
# certificate: "MII....."
```

Now a secondary, configure the replication node config.

```toml
[replication]
# ...

[replication."repl://origin_of_A:port"]
type = "mutual-pull"
partner_cert = "MII... <as output from A show-replication-cert>"
automatic_refresh = true
```

Now we must configure A to pull from B.

```bash
# Server B
docker exec -i -t <container name> \
  kanidmd show-replication-certificate
# certificate: "MII....."
```

Now on node A, configure the replication node config. It is critical here that you do NOT set `automatic_refresh`.

```toml
[replication]
# ...

[replication."repl://origin_of_B:port"]
type = "mutual-pull"
partner_cert = "MII... <as output from B show-replication-cert>"
# automatic_refresh = false
```

Then restart both servers. B (secondary) will automatically refresh from A (primary) and then replication will continue
bi-directionally from that point.
