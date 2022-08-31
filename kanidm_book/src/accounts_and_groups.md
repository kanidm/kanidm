# Accounts and groups

Accounts and Groups are the primary reasons for Kanidm to exist. Kanidm is optimised as a repository
for these data. As a result, there are many concepts and important details to understand.

## Service Accounts vs Person Accounts

Kanidm seperates accounts into two types. Person accounts (or persons) are intended for use by humans
that will access the system in an interactive way. Service accounts are intentded for use by computers
or services that need to identify themself to Kanidm. Generally a person or group of persons will
be responsible for and will manage service accounts. Because of this distinction these classes of
accounts have different properties and methods of authentication and management.

## Groups

Groups represent a collection of entities. This generally is a collection of persons or service accounts.
Groups are commonly used to assign privileges to the accouts that are members of a group. This allows
easier administration over larger systems where privileges can be assigned to groups in a logical
manner, and then only membership of the groups need administration, rather than needing to assign
privileges to each entity directly and uniquely.

Groups may also be nested, where a group can contain another group as a member. This allows hierarchies
to be created again for easier administration.

## Default Accounts and Groups

Kanidm ships with a number of default service accounts and groups. This is to give you the best
out-of-box experience possible, as well as supplying best practice examples related to modern
Identity Management (IDM) systems.

There are two builtin system administration accounts.

`admin` is the default service account which has privileges to configure and administer kanidm as a whole.
This account can manage access controls, schema, integrations and more. However the `admin` can not
manage persons by default to seperate the priviliges. As this is a service account is is intended
for limited use.

`idm_admin` is the default service account which has privileges to create persons and to manage these
accounts and groups. They can perform credential resets and more.

Both the `admin` and the `idm_admin` user should *NOT* be used for daily activities - they exist for initial
system configuration, and for disaster recovery scenarios. You should delegate permissions
as required to named user accounts instead.

The majority of the builtin groups are privilige groups that provide rights over Kanidm
administrative actions. These include groups for account management, person management (personal
and sensitive data), group management, and more.

## Recovering the Initial Admin Accounts

By default the `admin` and `idm_admin` accounts have no password, and can not be accessed. They need
to be "recovered" from the server that is running the kanidmd server.

{{#template
    templates/kani-warning.md
    imagepath=images
    text=Warning: The server must not be running at this point, as it requires exclusive access to the database.
}}

```shell
kanidmd recover_account admin -c /etc/kanidm/server.toml
# Successfully recovered account 'admin' - password reset to -> j9YUv...
```

To do this with Docker, you'll need to stop the existing container and use the "command" argument to
access the kanidmd binary.

```shell
docker run --rm -it \
    -v/tmp/kanidm:/data\
    --name kanidmd \
    --hostname kanidmd \
    kanidm/server:latest \
    kanidmd recover_account admin -c /data/server.toml
```

After the recovery is complete the server can be started again.

Once you have access to the admin account, it is able to reset the credentials of the `idm_admin`
account.

```shell
kanidm login -D admin
kanidm service-account credential generate-pw -D admin idm_admin
# Success: wJX...
```

These accounts will be used through the remainder of this document for managing the server.

## Viewing Default Groups

You should take some time to inspect the default groups which are related to
default permissions. These can be viewed with:

```
kanidm group list
kanidm group get <name>
```

## Creating Person Accounts

By default `idm_admin` has the privileges to create new persons in the system.

```shell
kanidm account create demo_user "Demonstration User" --name idm_admin
kanidm account get demo_user --name idm_admin

kanidm group create demo_group --name idm_admin
kanidm group add_members demo_group demo_user --name idm_admin
kanidm group list_members demo_group --name idm_admin
```

You can also use anonymous to view accounts and groups - note that you won't see certain fields due
to the limits of the access control anonymous access profile.

```
kanidm login --name anonymous
kanidm account get demo_user --name anonymous
```

Kanidm allows person accounts to include human related attributes, such as their legal name and email address.

Initially, a person does not have these attributes. If desired, a person may be modified to have these attributes.

```shell
# Note, both the --legalname and --mail flags may be omitted
kanidm account person update demo_user --legalname "initial name" --mail "initial@email.address"
```

{{#template
    templates/kani-warning.md
    imagepath=images
    text=Warning: Persons may change their own displayname, name, and legal name at any time. You MUST not use these values as primary keys in external systems. You MUST use the `uuid` attribute present on all entries as an external primary key.
}}

## Resetting Person Account Credentials

Members of the `idm_account_manage_priv` group have the rights to manage person and service
accounts security and login aspects. This includes resetting account credentials.

You can perform a password reset on the demo_user, for example as the idm_admin user, who is
a default member of this group. The lines below prefixed with `#` are the interactive credential
update interface.

```shell
kanidm account credential update demo_user --name idm_admin
# spn: demo_user@idm.example.com
# Name: Demonstration User
# Primary Credential:
# uuid: 0e19cd08-f943-489e-8ff2-69f9eacb1f31
# generated password: set
# Can Commit: true
# 
# cred update (? for help) # : pass
# New password: 
# New password: [hidden]
# Confirm password: 
# Confirm password: [hidden]
# success
# 
# cred update (? for help) # : commit
# Do you want to commit your changes? yes
# success
kanidm login --name demo_user
kanidm self whoami --name demo_user
```

## Creating Service Accounts

The `admin` service account can be used to create service accounts.

```shell
kanidm service-account create demo_service "Demonstration Service" --name admin
kanidm service-account get demo_service --name admin
```

## Resetting Service Account Credentials

Service accounts can not have their credentials interactively updated in the same manner as
persons. Service accounts may only have server side generated high entropy passwords.

To re-generate this password to an account

```shell
kanidm service-account credential generate-pw demo_service --name admin
```

## Nested Groups

Kanidm supports groups being members of groups, allowing nested groups. These nesting relationships
are shown through the "memberof" attribute on groups and accounts.

Kanidm makes all group membership determinations by inspecting an entry's "memberof" attribute.

An example can be easily shown with:

```shell
kanidm group create group_1 --name idm_admin
kanidm group create group_2 --name idm_admin
kanidm account create nest_example "Nesting Account Example" --name idm_admin
kanidm group add_members group_1 group_2 --name idm_admin
kanidm group add_members group_2 nest_example --name idm_admin
kanidm account get nest_example --name anonymous
```

## Account Validity

Kanidm supports accounts that are only able to be authenticated to between specific date and time
date where authentication can succeed, and an expiry date where the account will no longer
be valid. This takes the form of a "valid from" attribute that defines the earliest start
allow authentication, and an "expire"s at which defines the end of the validity period.

This can be displayed with:

    kanidm account validity show demo_user --name idm_admin
    valid after: 2020-09-25T21:22:04+10:00
    expire: 2020-09-25T01:22:04+10:00

These datetimes are stored in the server as UTC, but presented according to your local system time
to aid correct understanding of when the events will occur.

To set the values, an account with account management permission is required (for example, idm_admin).

You may set these time and date values in any timezone you wish (such as your local timezone), and the
server will transform these to UTC. These time values are in iso8601 format, and you should specify this
as:

```
YYYY-MM-DDThh:mm:ssZ+-hh:mm
Year-Month-Day T hour:minutes:seconds Z +- timezone offset
```

Set the earliest time the account can start authenticating:

```shell
kanidm account validity begin_from demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```
    
Set the expiry or end date of the account:

```shell
kanidm account validity expire_at demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```

To unset or remove these values the following can be used, where `any|clear` means you may use either `any` or `clear`.

```shell
kanidm account validity begin_from demo_user any|clear --name idm_admin
kanidm account validity expire_at demo_user never|clear --name idm_admin
```

To "lock" an account, you can set the expire_at value to the past, or unix epoch. Even in the situation
where the "valid from" is *after* the expire_at, the expire_at will be respected.

    kanidm account validity expire_at demo_user 1970-01-01T00:00:00+00:00 --name idm_admin

These validity settings impact all authentication functions of the account (kanidm, ldap, radius).

### Allowing people accounts to change their mail attribute

By default, Kanidm allows an account to change some attributes, but not their
mail address.

Adding the user to the `idm_people_self_write_mail` group, as shown
below, allows the user to edit their own mail.

    kanidm group add_members idm_people_self_write_mail_priv demo_user --name idm_admin

## Why Can't I Change admin With idm_admin?

As a security mechanism there is a distinction between "accounts" and "high permission
accounts". This is to help prevent elevation attacks, where say a member of a
service desk could attempt to reset the password of idm_admin or admin, or even a member of
HR or System Admin teams to move laterally.

Generally, membership of a "privilege" group that ships with Kanidm, such as:

* idm_account_manage_priv
* idm_people_read_priv
* idm_schema_manage_priv
* many more ...

...indirectly grants you membership to "idm_high_privilege". If you are a member of
this group, the standard "account" and "people" rights groups are NOT able to
alter, read or manage these accounts. To manage these accounts higher rights
are required, such as those held by the admin account are required.

Further, groups that are considered "idm_high_privilege" can NOT be managed
by the standard "idm_group_manage_priv" group.

Management of high privilege accounts and groups is granted through the
the "hp" variants of all privileges. A non-conclusive list:

* idm_hp_account_read_priv
* idm_hp_account_manage_priv
* idm_hp_account_write_priv
* idm_hp_group_manage_priv
* idm_hp_group_write_priv

Membership of any of these groups should be considered to be equivalent to
system administration rights in the directory, and by extension, over all network
resources that trust Kanidm.

All groups that are flagged as "idm_high_privilege" should be audited and
monitored to ensure that they are not altered.
