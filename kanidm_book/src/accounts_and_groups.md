# Accounts and groups

Accounts and Groups are the primary reasons for Kanidm to exist. Kanidm is optimised as a repository
for these data. As a result, there are many concepts and important details to understand.

## Default Accounts and Groups

Kanidm ships with a number of default accounts and groups. This is to give you the best 
out-of-box experience possible, as well as supplying best practice examples related to modern 
Identity Management (IDM) systems.

The system administrator account has limited privileges (see 
[Recovering the Initial idm_admin Account](#recovering-the-initial-idm_admin-account)) to learn 
how to access the inbuilt admin account).
It manages only high-privilege accounts and services. This is to help separate system administration
from identity administration actions. An idm_admin user is also provided that is only for management
of accounts and groups.

Both the admin and the idm_admin user should *NOT* be used for daily activities - they exist for initial
system configuration, and for disaster recovery scenarios. You should delegate permissions
as required to named user accounts instead.

The majority of the provided content is privilege groups that provide rights over Kanidm
administrative actions. These include groups for account management, person management (personal
and sensitive data), group management, and more.

## Recovering the Initial idm_admin Account

By default the idm_admin user has no password, and can not be accessed. You should recover it with the
admin (system admin) account. We recommend the use of the "recover_account" functionalit as it provides a high strength, random password.

<table>
<tr>
<td>
<img src="/images/kani-warning.png" style="float:left">
</td>
<td>Warning: The server must not be running at this point, as it requires raw access to the database.</td>
</tr>
</table>


```shell
kanidmd recover_account  --name admin idm_admin
Successfully recovered account 'idm_admin' - password reset to -> j9YUv...
```

## Creating Accounts

You can now use the idm_admin user to create initial groups and accounts.

```shell
kanidm login --name idm_admin
kanidm group create demo_group --name idm_admin
kanidm account create demo_user "Demonstration User" --name idm_admin
kanidm group add_members demo_group demo_user --name idm_admin
kanidm group list_members demo_group --name idm_admin
kanidm account get demo_user --name idm_admin
```

You can also use anonymous to view users and groups - note that you won't see as many fields due
to the limits of the anonymous access profile.

    kanidm login --name anonymous
    kanidm account get demo_user --name anonymous

## Viewing Default Groups

You should take some time to inspect the default groups which are related to
default permissions. These can be viewed with:

    kanidm group list
    kanidm group get <name>

## Resetting Account Credentials

Members of the `idm_account_manage_priv` group have the rights to manage other users'
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

Kanidm supports accounts that are only able to be authenticated between specific date and time
date where authentication can succeed, and an expiry date where the account will no longer
windows. This takes the form of a "valid from" attribute that defines the earliest start
allow authentication.

This can be displayed with:

    kanidm account validity show demo_user --name idm_admin
    valid after: 2020-09-25T21:22:04+10:00
    expire: 2020-09-25T01:22:04+10:00

These datetimes are stored in the server as UTC, but presented according to your local system time
to aid correct understanding of when the events will occur.

To set the values, an account with account management permission is required (for example, idm_admin).
Again, these values will correctly translated from the entered local timezone to UTC.

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

## People Accounts

Kanidm allows extending accounts to include additional "people" attributes,
such as their legal name and email address.

Initially, an account does not have these attributes. If desired, an account
may be modified to have these "person" attributes like so:

    # Note, both the --legalname and --mail flags may be omitted
    kanidm account person extend demo_user --legalname "initial name" --mail "initial@email.address"

Once an account has been extended, the "person" attributes may be set by the
user of the account, or anyone with enough privileges.

Whether an account is currently a "person" or not can be identified from the "account get" output:

    kanidm account get demo_user
    # ---
    # class: person
    # ... (other output omitted)

The presence of a "class: person" stanza indicates that this account may have
"people" attributes.

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
