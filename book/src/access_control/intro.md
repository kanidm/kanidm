# Access Control

While Kanidm exists to make authorisation decisions on behalf of other services, internally it must make decisions about
writes operations to the entries within its database. To make these choices, Kanidm has an internal set of access
controls which are the rules describing who may perform what actions.

## Default Permissions

The project ships default access controls which are designed to limit and isolate the privileges of accounts whenever
possible.

This separation is the reason why `admins` and `idm_admins` exist as separate groups. There are two distinct access
silos within Kanidm. Access to manage Kanidm as a service (such as application integrations and domain naming) and
access to manage people and groups. This is to limit the possible harm that an attacker may make if they gain access to
these roles.

## Assigning Permissions to Persons

Kanidm supports [privilege access mode](../accounts/authentication_and_credentials.md) so that high-level permissions
can be assigned to users who must reauthenticate before using those privileges. The privileges then are only accessible
for a short period of time. This can allow you to assign high level permissions to regular person accounts rather than
requiring separate privilege access accounts (PAA) or privileged access workstations (PAW).

## Assigning Permissions to Service Accounts

Service account tokens can be issued with read-only or read-write flags, where read-only tokens are unable to modify
content of Kanidm. This can allow the service account to have higher level permissions assigned but only usable with a
short lived or isolated read-write token.

## Permission Delegation

A number of types in Kanidm allow permission delegation such as groups and service accounts. This allows entries to be
assigned an entry manager who has write access to that entity but not all entities of the same class.

## High Privilege Groups

Kanidm has a special group called `idm_high_privilege`. This acts as a "taint" on its members to indicate that they have
an elevated level of access within Kanidm or other systems.

This taint flag exists to prevent lateral movement from other roles that have higher levels of privilege.

An example is `idm_service_desk` which has the ability to trigger credential resets for users. This is an important
aspect of the service desk role. However, a member of the service desk should not be able to modify the credentials of
their peers, nor should they be able to escalate by accessing the credentials of users in a role such as `idm_admins`.
Since `idm_service_desk` and `idm_admins` are both tainted with `idm_high_privilege` then this lateral movement is not
possible. Only high privileged roles are able to then reset the accounts of high privilege users.

You may add other groups to `idm_high_privilege` to achieve the same taint effect for other services.

## Default Permission Groups

Kanidm ships with default permission groups. You can use these to enable (or disable) accounts to performing certain
actions or tasks within Kanidm as required by modifying the memberships of these groups.

| group name                   | description                                                                  |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `domain_admins`              | modify the name of this domain                                               |
| `idm_access_control_admins`  | write access controls                                                        |
| `idm_account_policy_admins`  | modify account policy requirements for user authentication                   |
| `idm_group_admins`           | create and modify groups                                                     |
| `idm_mail_servers`           | read mail attributes needed to be a mail server                              |
| `idm_mail_service_admins`    | grant permissions to service accounts to act as mail servers                 |
| `idm_oauth2_admins`          | create and modify OAuth2 integrations                                        |
| `idm_people_admins`          | create and modify persons                                                    |
| `idm_people_on_boarding`     | create (but not modify) persons. Intended for use with service accounts      |
| `idm_people_pii_read`        | allow read to personally identifying information                             |
| `idm_people_self_mail_write` | allow self-modification of the mail attribute                                |
| `idm_people_self_name_write` | allow self-modification of the name related attributes                       |
| `idm_radius_servers`         | read user radius secrets. Intended for use with service accounts             |
| `idm_radius_service_admins`  | create and reset user radius secrets, and allow users to access radius       |
| `idm_recycle_bin_admins`     | modify and restore entries from the recycle bin                              |
| `idm_schema_admins`          | add and modify elements of schema                                            |
| `idm_service_account_admins` | create and modify service accounts                                           |
| `idm_unix_admins`            | enable posix attributes on accounts and groups                               |
| `idm_application_admins`     | create and modify ldap applications which use per-user application passwords |

## Default Roles

Kanidm ships with 3 high level permission groups. These roles have no inherent permissions, they are created by being
members of the default permission groups.

| group name         | description                                              |
| ------------------ | -------------------------------------------------------- |
| `idm_admins`       | manage persons and their groups                          |
| `idm_service_desk` | assist persons with credential resets or other queries   |
| `system_admins`    | manage the operation of Kanidm as a database and service |
