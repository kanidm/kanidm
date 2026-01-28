# Config Management Entries

One of the most requested features (especially from the nix community 📆 ) is the ability to config
manage entries that exist in Kanidm.

To this point, we have not had a way to do this - there are many reasons, but part is that we wanted
to do this "right". Another part is we didn't have a good approach in mind that would work with a
distributed system like Kanidm.

But guess what, we're finally doing it. 🎉

> NOTE this design does NOT account for secret management - yet. That will be a later/subsequent change.

## The Risks

Kanidm is by it's nature, a distributed system with eventually consistent replication. This makes
it very difficult to *manage* entries because any difference between multiple nodes in the
system will cause a "fight" where the nodes will compete for the state of the entry.

As a result, we need a way to allow entry creation that can work in a distributed system, where there
may be *inconsistent* application of the configurations.

This presents a challenge - how can we ensure a total *ordering* of the applied configurations, while
also ensuring that updates take precedence? How can we also ensure that human changes that are made
are preserved in this system? And how do we ensure that updates to the configuration are applied
as expected over existing data?

## The Design

There will be a drop in directory where SCIM formatted JSON entries can be placed. These will be based
on a modified SCIM "assert" that combines create/put to assert a state in an entry. If the entry
does not exist it will be created. If it does exist it will be altered to be inline with the state
of the assertion.

When Kanidm starts, after migrations are applied this directory will be listed in order and the files
applied. A *hash* of the applied file is taken and stored in the database.

When Kanidm is *restarted*, any configuration file that has already been applied, and who's hash
matches in the database will *not be re-applied*.

This means that the configuration entries become a once-off-change.

What this scheme also allows is that on a replica node it will NOT apply changes that were already
applied and in the database. It also means that configuration management can exist on a single node
or all nodes, and the same effect will result on all. If two nodes have competing and conflicting
configuration management entries, only one will persist, and application fights will not occur.

However if a new file is added, since the file has not been seen or hashed, it will be applied. If
a file is updated, it will be applied as well.

This gives precedence to "newest changes win" in the database, but without affecting the past
state of applied data. This means that if something occurs that the admin believes is incorrect
they can update a drop in to correct the data, and have it applied.

## Limitations

The major limitation is that changes are made *once*.

Consider we have two nodes and they have divergent configurations for an entry. If we continually
polled and applied the changes, then each replication the nodes would be "fighting" over the state
of the entry.

Similar, if a human makes a change to an entry, then the configuration manager could undo that against
the humans will.

As with anything there are trades - pros and cons. We think that having configuration management entries
run *once* means that admins won't accidentaly undo a human made change, but also means that when
an admin updates an entry then there is intent behind that change and it can apply to the entry.

We will also need to ensure that the scope of what entries can be altered by this system has constraints.
For example, we will start to introduce group, person and service-accounts, but other entries may
not be managed by this scheme.

## Future

### Secret Management

Secret management is a really tough thing to do right with configuration management. We don't want
secrets to be plaintext and added onto disk either on the server, or on the laptop of a user. But we
also don't want user-generated secrets as these may be weak or insecure.

A future method of secret management maybe the usage of a nonce in the configuration management system.
This nonce will be fed to a HMAC-KDF to derive the true secret. This allows a user with access to the
HMAC key to also derive the true secret, but without it ever being committed to disk on any machine.

However this does introduce a high value key that all other secrets are derived from. This in itself
presents a large risk. This is why secret management is not yet on the table as it has a high risk
of compromise if we get it wrong.
