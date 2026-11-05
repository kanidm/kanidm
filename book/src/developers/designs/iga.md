# Identity Governance and Administration (IGA)

An IGA can be used to automate and audit resource access within a technical environment. The IGA
will also support a Joiner, Mover and Leaver (JML) process.

In practice it will look like this:

Join:

> 1. An employee joins a company
> 2. The HR system sends employment data to the IGA (department, title, etc)
> 3. The IGA role engine calculates their resources based on data from HR
>    1. An account in the Kanidm system
>    2. Kanidm group to log in to computers
>    3. Kanidm group to access network shares
>    4. An employee badge
>    5. Relevant groups in the office building's access control system so the employee can access their office
> 4. The IGA then provisions (synchronises) these resources with relevant target systems (Kanidm,
   building's access control, etc)

Move:

> 1. The employee gets a new title in a new department
> 2. HR sends new data to IGA
> 3. Role engine removes manually added resources and recalculate resources
> 4. Removed resources are deprovisioned, and added are provisioned in target systems

Leave:

> 1. The employee leaves
> 2. HR sends new data to IGA
> 3. Role engine removes all resources
> 4. Resources are deprovisioned in target system.

Please notice that a move can simply be implemented as a leave and join in quick succession.

## Role Engine

## Manual resources

To better support various business use cases, it's important to be able to attach resources that're
not calculated by the role engine. This way it's possible to have employees with same title have
separate permissions when necessary.

## Base data types

The following data types can be extended to better support business cases. This includes having
various types of types, like for identity it could be person, machine, workload etc. It could also
be adding additional attributes to each variant, like home address for person if necessary for
logging reasons.

### Identity

An identity should be mapped as close as 1:1 to a person* as possible. The identity should not be
mistaken for an account, as a person can have multiple accounts across multiple systems, and
sometimes multiple accounts on the same system. This also covers use cases like having a personal
account for everyday work, but also a privileged account fro adminastative tasks.

* an identity can also be a machine, workload, with extendable data types, whatever suits your
business case.

### Context

A context is what "binds" an identity to their resources. Usually a context is an employment, this
way the IGA supports multi affiliation (think a nurse who is also a paramedic).

Contexts can expire, and when they do, the role engine will recalculate effective resources and thus
start a leave process for that specific context.

With custom context types it's also possible to support advanced use case. Examples includes
hooking the IGA up to a project management system as a pseudo HR system, and creating project
contexts so the person gets short lived resources for the duration of their participation in a
project. This of course also includes manual resources, so a developer automatically gets removed
from a git repo when they're no longer part of the project.

And naturally contexts can also get custom attributes, to support advanced role calculations.

### Bucket

A bucket is a collection of resources or buckets. These buckets is where the rules and filters lives
and exists to both support the role engine as well as logically grouping resources. Bucket rules are
often based on contexts, like department and title filters, or projects or similar. A bucket is the
only type that never exists outside the IGA (unless you're building them with Terraform).

The name bucket was chosen in favor of role or group to not confuse terminology with target systems
where these might be in use and thus have different semantic meanings.

### Resource

A resource in its nature is what the IGA is build to support. These are "anything" a user would want
access to in a target system, usually this is groups or permissions, but can also be something like
a physical lock or even a device. In this way a resource only maps to a single resource in a given application.

Resources, like the other types, can be extended by application and target systems to support
various needs. Sometimes it's important to have more attributes than is provided by default, like
phone model and IMEI, or floor and room.

Resources can also in themselves become reason to provision a context or an account, in a way make
the role engine control what happens to the identity and its resources.

### Account

An account is what the resource is attached to in the target system. Often times it's something
concrete like a Kanidm user, other times it's a bit of a misnomer, like for example is a badge an
account? The best way to think of an account is probably the target systems idea of an identity, and
it holds identities.

To simplify the role engine, an identity can only have one of each type of account. So in Kanidm it
would probably be a personal account and an administrative account. Additionally an account should
only exist if the identity has a resource for said account, so please remember to make a bucket that
hits everyone and gives them a Kanidm account ;) .

## Connectors
