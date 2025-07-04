# Administration

## Renew Replication Identity Certificate

The replication identity certificate defaults to an expiry of 180 days.

To renew this run the command:

```bash
docker exec -i -t <container name> \
  kanidmd renew-replication-certificate
# certificate: "MII....."
```

You must then copy the new certificate to other nodes in the topology.

> [!NOTE]
>
> In the future we will develop a replication coordinator so that you don't have to manually renew this. But for now, if
> you want replication, you have to do it the hard way.

## Refresh a Lagging Consumer

If a consumer has been offline for more than 7 days, its error log will display that it requires a refresh.

You can manually perform this on the affected node.

```bash
docker exec -i -t <container name> \
  kanidmd refresh-replication-consumer
```
