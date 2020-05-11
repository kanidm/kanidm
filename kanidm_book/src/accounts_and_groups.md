# Accounts and groups

Accounts and Groups are the primary reason for Kanidm to exist. Kanidm is optimised as a repository
for these data. As a result, they have many concepts and important details to understand.

## Default Accounts and Groups

Kanidm ships with a number of default accounts and groups. This is to give you the best out of
box experience possible, as well as supplying best practice examples related to modern IDM
systems.

The system admin account (the account you recovered in the setup) has limited privileges - only to
manage high-privilege accounts and services. This is to help separate system administration
from identity administration actions. An idm_admin is also provided that is only for management
of accounts and groups.

Both admin and idm_admin should *NOT* be used for daily activities - they exist for initial
system configuration, and for disaster recovery scenarios. You should delegate permissions
as required to named user accounts instead.

The majority of the provided content is privilege groups that provide rights over Kanidm
administrative actions. These include groups for account management, person management (personal
and sensitive data), group management, and more.

## Recovering the Initial idm_admin Account

By default the idm_admin has no password, and can not be accessed. You should recover it with the
admin (system admin) account. We recommend the use of "generate_password" as it provides a high
strength, random, machine only password.

    kanidm account credential generate_password  --name admin idm_admin
    Generated password for idm_admin: tqoReZfz....

We can now use the idm_admin to create initial groups and accounts.

    kanidm group create demo_group --name idm_admin
    kanidm account create demo_user "Demonstration User" --name idm_admin
    kanidm group add_members demo_group demo_user --name idm_admin
    kanidm group list_members demo_group --name idm_admin
    kanidm account get demo_user --name idm_admin

You can also use anonymous to view users and groups - note that you won't see as many fields due
to the different anonymous access profile limits!

    kanidm account get demo_user --name anonymous

## Viewing Default Groups

You should take some time to inspect the default groups which are related to
default permissions. These can be viewed with:

    kanidm group list
    kanidm group get <name>

## Resetting Account Credentials

Members of the `idm_account_manage_priv` group have the rights to manage other users
accounts security and login aspects. This includes resetting account credentials.

We can perform a password reset on the demo_user for example as idm_admin, who is
a default member of this group.

    kanidm account credential set_password demo_user --name idm_admin
    kanidm self whoami --name demo_user

## Nested Groups

Kanidm supports groups being members of groups, allowing nested groups. These nesting relationships
are shown through the "memberof" attribute on groups and accounts.

Kanidm makes all group-membership determinations by inspecting an entries "memberof" attribute.

An example can be easily shown with:

    kanidm group create group_1 --name idm_admin
    kanidm group create group_2 --name idm_admin
    kanidm account create nest_example "Nesting Account Example" --name idm_admin
    kanidm group add_members group_1 group_2 --name idm_admin
    kanidm group add_members group2 nest_example --name idm_admin
    kanidm account get nest_example --name anonymous

## Why Can't I Change admin With idm_admin?

As a security mechanism there is a distinction between "accounts" and "high permission
accounts". This is to help prevent elevation attacks, where say a member of a
service desk could attempt to reset the password of idm_admin or admin, or even a member of
HR or System Admin teams to move laterally.

Generally, membership of a "privilege" group that ships with kanidm, such as:

* idm_account_manage_priv
* idm_people_read_priv
* idm_schema_manage_priv
* many more ...

Indirectly grants you membership to "idm_high_privilege". If you are a member of
this group, the standard "account" and "people" rights groups are NOT able to
alter, read or manage these accounts. To manage these accounts higher rights
are required, such as those held by the admin account are required.

Further, groups that are considered "idm_high_privilege" can NOT be managed
by the standard "idm_group_manage_priv" group.

Management of high privilege accounts and groups is granted through the
the "hp" variants of all privileges. For example:

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
