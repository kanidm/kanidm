# Accounts and groups

Accounts and Groups are the primary reasons for Kanidm to exist. Kanidm is optimised as a repository for these data. As
a result, there are many concepts and important details to understand.

## Service Accounts vs Person Accounts

Kanidm separates accounts into two types. Person accounts (or persons) are intended for use by humans that will access
the system in an interactive way. Service accounts are intended for use by computers or services that need to identify
themself to Kanidm. Generally a person or group of persons will be responsible for and will manage service accounts.
Because of this distinction these classes of accounts have different properties and methods of authentication and
management.

## Groups

Groups represent a collection of entities. This generally is a collection of persons or service accounts. Groups are
commonly used to assign privileges to the accounts that are members of a group. This allows easier administration over
larger systems where privileges can be assigned to groups in a logical manner, and then only membership of the groups
need administration, rather than needing to assign privileges to each entity directly and uniquely.

Groups may also be nested, where a group can contain another group as a member. This allows hierarchies to be created
again for easier administration.

## Default Accounts and Groups

Kanidm ships with a number of default service accounts and groups. This is to give you the best out-of-box experience
possible, as well as supplying best practice examples related to modern Identity Management (IDM) systems.

There are two "break-glass" system administration accounts.

`admin` is the default service account which has privileges to configure and administer Kanidm as a whole. This account
can manage access controls, schema, integrations and more. However the `admin` can not manage persons by default.

`idm_admin` is the default service account which has privileges to create persons and to manage these accounts and
groups. They can perform credential resets and more.

Both the `admin` and the `idm_admin` user should _NOT_ be used for daily activities - they exist for initial system
configuration, and for disaster recovery scenarios. You should delegate permissions as required to named user accounts
instead.

The majority of the builtin groups are privilege groups that provide rights over Kanidm administrative actions. These
include groups for account management, person management (personal and sensitive data), group management, and more.

`admin` and `idm_admin` both inherit their privileges from these default groups. This allows you to assign persons to
these roles instead.

## Reauthentication and Session Privilege

Kanidm sessions have a concept of session privilege. Conceptually you can consider this like `sudo` on unix systems or
`uac` on windows. This allows a session to briefly access its write permissions by reauthentication with the identical
credential they logged in with.

This allows safe assignment of high privilege roles to persons since their sessions do not have access to their write
privileges by default. They must reauthenticate and use their privileges within a short time window.

However, these sessions always retain their _read_ privileges - meaning that they can still access and view high levels
of data at any time without reauthentication.

In high risk environments you should still consider assigning separate administration accounts to users if this is
considered a risk.

## Recovering the Initial Admin Accounts

By default the `admin` and `idm_admin` accounts have no password, and can not be accessed. They need to be "recovered"
from the server that is running the kanidmd server.

You should have already recovered the admin account during your setup process. If not, refer to the
[server configuration chapter](../server_configuration.md#default-admin-account) on how to recover these accounts.

These accounts will be used through the remainder of this document for managing the server.

## Viewing Default Groups

You should take some time to inspect the default groups which are related to default roles and permissions. Each group
has a description to explain its purpose. These can be viewed with:

```bash
kanidm group list --name idm_admin
kanidm group get <name>
```
