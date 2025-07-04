# Planning

It is important that you plan your replication deployment before you proceed. You may have a need for high availability
within a datacentre, geographic redundancy, or improvement of read scaling.

## Improvement of Read Throughput

Addition of replicas can improve the amount of read and authentication operations performed over the topology as a
whole. This is because read operations throughput is additive between nodes.

For example, if you had two servers that can process 1000 authentications per second each, then when in replication the
topology can process 2000 authentications per second.

However, while you may gain in read throughput, you must account for downtime - you should not always rely on every
server to be online.

The optimal loading of any server is approximately 50%. This allows overhead to absorb load if nearby nodes experience
outages. It also allows for absorption of load spikes or other unexpected events.

It is important to note however that as you add replicas the _write_ throughput does not increase in the same way as
read throughput. This is because for each write that occurs on a node, it must be replicated and written to every other
node. Therefore your write throughput is always bounded by the _slowest_ server in your topology. In reality there is a
"slight" improvement in writes due to coalescing that occurs as part of replication, but you should assume that writes
are not improved through the addition of more nodes.

## Directing Clients to Live Servers

Operating replicas of Kanidm allows you to minimise outages if a single or multiple servers experience downtime. This
can assist you with patching and other administrative tasks that you must perform.

However, there are some key limitations to this fault tolerance.

You require a method to fail over between servers. This generally involves a load balancer, which itself must be fault
tolerant. Load balancers can be made fault tolerant through the use of protocols like `CARP` or `VRRP`, or by
configuration of routers with anycast.

If you elect to use `CARP` or `VRRP` directly on your Kanidm servers, then be aware that you will be configuring your
systems as active-passive, rather than active-active, so you will not benefit from improved read throughput. Contrast,
anycast will always route to the closest Kanidm server and will failover to nearby servers so this may be an attractive
choice.

You should _NOT_ use DNS based failover mechanisms as clients can cache DNS records and remain "stuck" to a node in a
failed state.

## Maximum Downtime of a Server

Kanidm's replication protocol enforces limits on how long a server can be offline. This is due to how tombstones
(deleted entries) are handled. By default the maximum is 7 days. If a server is offline for more than 7 days a refresh
will be required for that server to continue participation in the topology.

It is important you avoid extended downtime of servers to avoid this condition.
