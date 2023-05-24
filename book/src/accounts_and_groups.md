# Accounts and groups

Accounts and Groups are the primary reasons for Kanidm to exist. Kanidm is optimised as a repository
for these data. As a result, there are many concepts and important details to understand.

## Service Accounts vs Person Accounts

Kanidm separates accounts into two types. Person accounts (or persons) are intended for use by
humans that will access the system in an interactive way. Service accounts are intended for use by
computers or services that need to identify themself to Kanidm. Generally a person or group of
persons will be responsible for and will manage service accounts. Because of this distinction these
classes of accounts have different properties and methods of authentication and management.

## Groups

Groups represent a collection of entities. This generally is a collection of persons or service
accounts. Groups are commonly used to assign privileges to the accounts that are members of a group.
This allows easier administration over larger systems where privileges can be assigned to groups in
a logical manner, and then only membership of the groups need administration, rather than needing to
assign privileges to each entity directly and uniquely.

Groups may also be nested, where a group can contain another group as a member. This allows
hierarchies to be created again for easier administration.

## Default Accounts and Groups

Kanidm ships with a number of default service accounts and groups. This is to give you the best
out-of-box experience possible, as well as supplying best practice examples related to modern
Identity Management (IDM) systems.

There are two builtin system administration accounts.

`admin` is the default service account which has privileges to configure and administer kanidm as a
whole. This account can manage access controls, schema, integrations and more. However the `admin`
can not manage persons by default to separate the privileges. As this is a service account is is
intended for limited use.

`idm_admin` is the default service account which has privileges to create persons and to manage
these accounts and groups. They can perform credential resets and more.

Both the `admin` and the `idm_admin` user should _NOT_ be used for daily activities - they exist for
initial system configuration, and for disaster recovery scenarios. You should delegate permissions
as required to named user accounts instead.

The majority of the builtin groups are privilege groups that provide rights over Kanidm
administrative actions. These include groups for account management, person management (personal and
sensitive data), group management, and more.

## Recovering the Initial Admin Accounts

By default the `admin` and `idm_admin` accounts have no password, and can not be accessed. They need
to be "recovered" from the server that is running the kanidmd server.

You should have already recovered the admin account during your setup process. If not refer to the
[server configuration chapter](server_configuration.md#default-admin-account) on how to recover this
account.

Once you have access to the admin account, it is able to reset the credentials of the `idm_admin`
account.

```bash
kanidm login -D admin
kanidm service-account credential generate -D admin idm_admin
# Success: wJX...
```

These accounts will be used through the remainder of this document for managing the server.

## Viewing Default Groups

You should take some time to inspect the default groups which are related to default permissions.
These can be viewed with:

```bash
kanidm group list
kanidm group get <name>
```

## Creating Person Accounts

By default `idm_admin` has the privileges to create new persons in the system.

```bash
kanidm login --name idm_admin
kanidm person create demo_user "Demonstration User" --name idm_admin
kanidm person get demo_user --name idm_admin

kanidm group create demo_group --name idm_admin
kanidm group add-members demo_group demo_user --name idm_admin
kanidm group list-members demo_group --name idm_admin
```

You can also use anonymous to view accounts and groups - note that you won't see certain fields due
to the limits of the access control anonymous access profile.

```bash
kanidm login --name anonymous
kanidm person get demo_user --name anonymous
```

Kanidm allows person accounts to include human related attributes, such as their legal name and
email address.

Initially, a person does not have these attributes. If desired, a person may be modified to have
these attributes.

```bash
# Note, both the --legalname and --mail flags may be omitted
kanidm person update demo_user --legalname "initial name" --mail "initial@email.address"
```

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=Warning!
text=Persons may change their own displayname, name, and legal name at any time. You MUST NOT use these values as primary keys in external systems. You MUST use the `uuid` attribute present on all entries as an external primary key.
}}

<!-- deno-fmt-ignore-end -->

## Creating Service Accounts

The `admin` service account can be used to create service accounts.

```bash
kanidm service-account create demo_service "Demonstration Service" --name admin
kanidm service-account get demo_service --name admin
```

## Using API Tokens with Service Accounts

Service accounts can have api tokens generated and associated with them. These tokens can be used
for identification of the service account, and for granting extended access rights where the service
account may previously have not had the access. Additionally service accounts can have expiry times
and other auditing information attached.

To show api tokens for a service account:

```bash
kanidm service-account api-token status --name admin ACCOUNT_ID
kanidm service-account api-token status --name admin demo_service
```

By default api tokens are issued to be "read only", so they are unable to make changes on behalf of
the service account they represent. To generate a new read only api token:

```bash
kanidm service-account api-token generate --name admin ACCOUNT_ID LABEL [EXPIRY]
kanidm service-account api-token generate --name admin demo_service "Test Token"
kanidm service-account api-token generate --name admin demo_service "Test Token" 2020-09-25T11:22:02+10:00
```

If you wish to issue a token that is able to make changes on behalf of the service account, you must
add the "--rw" flag during the generate command. It is recommended you only add --rw when the
api-token is performing writes to Kanidm.

```bash
kanidm service-account api-token generate --name admin ACCOUNT_ID LABEL [EXPIRY] --rw
kanidm service-account api-token generate --name admin demo_service "Test Token" --rw
kanidm service-account api-token generate --name admin demo_service "Test Token" 2020-09-25T11:22:02+10:00 --rw
```

To destroy (revoke) an api token you will need it's token id. This can be shown with the "status"
command.

```bash
kanidm service-account api-token destroy --name admin ACCOUNT_ID TOKEN_ID
kanidm service-account api-token destroy --name admin demo_service 4de2a4e9-e06a-4c5e-8a1b-33f4e7dd5dc7
```

Api tokens can also be used to gain extended search permissions with LDAP. To do this you can bind
with a dn of `dn=token` and provide the api token in the password.

```bash
ldapwhoami -H ldaps://URL -x -D "dn=token" -w "TOKEN"
ldapwhoami -H ldaps://idm.example.com -x -D "dn=token" -w "..."
# u: demo_service@idm.example.com
```

## Resetting Service Account Credentials (Deprecated)

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
text=Api Tokens are a better method to manage credentials for service accounts, and passwords may be removed in the future!
}}

<!-- deno-fmt-ignore-end -->

Service accounts can not have their credentials interactively updated in the same manner as persons.
Service accounts may only have server side generated high entropy passwords.

To re-generate this password to an account

```bash
kanidm service-account credential generate demo_service --name admin
```

## Nested Groups

Kanidm supports groups being members of groups, allowing nested groups. These nesting relationships
are shown through the "memberof" attribute on groups and accounts.

Kanidm makes all group membership determinations by inspecting an entry's "memberof" attribute.

An example can be easily shown with:

```bash
kanidm group create group_1 --name idm_admin
kanidm group create group_2 --name idm_admin
kanidm person create nest_example "Nesting Account Example" --name idm_admin
kanidm group add-members group_1 group_2 --name idm_admin
kanidm group add-members group_2 nest_example --name idm_admin
kanidm person get nest_example --name anonymous
```

## Account Validity

Kanidm supports accounts that are only able to authenticate between a pair of dates and times; the
"valid from" and "expires" timestamps define these points in time.

This can be displayed with:

```bash
kanidm person validity show demo_user --name idm_admin
valid after: 2020-09-25T21:22:04+10:00
expire: 2020-09-25T01:22:04+10:00
```

These datetimes are stored in the server as UTC, but presented according to your local system time
to aid correct understanding of when the events will occur.

To set the values, an account with account management permission is required (for example,
idm_admin).

You may set these time and date values in any timezone you wish (such as your local timezone), and
the server will transform these to UTC. These time values are in iso8601 format, and you should
specify this as:

```shell
YYYY-MM-DDThh:mm:ssZ+-hh:mm
Year-Month-Day T hour:minutes:seconds Z +- timezone offset
```

Set the earliest time the account can start authenticating:

```bash
kanidm person validity begin_from demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```

Set the expiry or end date of the account:

```bash
kanidm person validity expire_at demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```

To unset or remove these values the following can be used, where `any|clear` means you may use
either `any` or `clear`.

```bash
kanidm person validity begin_from demo_user any|clear --name idm_admin
kanidm person validity expire_at demo_user never|clear --name idm_admin
```

To "lock" an account, you can set the expire_at value to the past, or unix epoch. Even in the
situation where the "valid from" is _after_ the expire_at, the expire_at will be respected.

```bash
kanidm person validity expire_at demo_user 1970-01-01T00:00:00+00:00 --name idm_admin
```

These validity settings impact all authentication functions of the account (kanidm, ldap, radius).

### Allowing people accounts to change their mail attribute

By default, Kanidm allows an account to change some attributes, but not their mail address.

Adding the user to the `idm_people_self_write_mail` group, as shown below, allows the user to edit
their own mail.

```bash
kanidm group add-members idm_people_self_write_mail_priv demo_user --name idm_admin
```

## Why Can't I Change admin With idm\_admin?

As a security mechanism there is a distinction between "accounts" and "high permission accounts".
This is to help prevent elevation attacks, where say a member of a service desk could attempt to
reset the password of idm\_admin or admin, or even a member of HR or System Admin teams to move
laterally.

Generally, membership of a "privilege" group that ships with Kanidm, such as:

- idm\_account\_manage\_priv
- idm\_people\_read\_priv
- idm\_schema\_manage\_priv
- many more ...

...indirectly grants you membership to "idm\_high\_privilege". If you are a member of this group,
the standard "account" and "people" rights groups are NOT able to alter, read or manage these
accounts. To manage these accounts higher rights are required, such as those held by the admin
account are required.

Further, groups that are considered "idm\_high\_privilege" can NOT be managed by the standard
"idm\_group\_manage\_priv" group.

Management of high privilege accounts and groups is granted through the the "hp" variants of all
privileges. A non-conclusive list:

- idm\_hp\_account\_read\_priv
- idm\_hp\_account\_manage\_priv
- idm\_hp\_account\_write\_priv
- idm\_hp\_group\_manage\_priv
- idm\_hp\_group\_write\_priv

Membership of any of these groups should be considered to be equivalent to system administration
rights in the directory, and by extension, over all network resources that trust Kanidm.

All groups that are flagged as "idm\_high\_privilege" should be audited and monitored to ensure that
they are not altered.
