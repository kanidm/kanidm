
# Access Profiles Rework 2022

Access controls are critical for a project like Kanidm to determine who can access what on other
entries. Our access controls have to be dynamic and flexible as administrators will want to define
their own access controls. In almost every call in the server, they are consulted to determine if
the action can be carried out. We also supply default access controls so that out of the box we are
a complete and useful IDM.

The original design of the access control system was intended to satisfy our need for flexibility,
but we have begun to discover a number of limitations. The design incorporating filter queries makes
them hard to administer as we have not often publicly talked about the filter language and how it
internally works. Because of their use of filters it is hard to see on an entry "what" access controls
will apply to entries, making it hard to audit without actually calling the ACP subsystem. Currently
the access control system has a large impact on performance, accounting for nearly 35% of the time taken
in a search operation.

Additionally, the default access controls that we supply have started to run into limits and rough cases
due to changes as we have improved features. Some of this was due to limited design with user cases
in mind during development.

To resolve this a number of coordinating features need implementation to improve this situation. These
features will be documented *first*, and the use cases *second* with each use case linking to the
features that satisfy it.

## Required Features to Satisfy

### Refactor of default access controls

The current default privileges will need to be refactored to improve seperation of privilege
and improved delegation of finer access rights.

### Access profiles target specifiers instead of filters

Access profiles should target a list of groups for who the access profile applies to, and who recieves
the access it is granting.

Alternately an access profile could target "self" so that self-update rules can still be expressed.

An access profile could target an oauth2 definition for the purpose of allowing reads to members
of a set of scopes that can access the service.

The access profile receiver would be group based only. This allows specifying that "X group of members
can write self" meaning that any member of that group can write to themself and only themself.

In the future we could also create different target/receiver specifiers to allow other extended management
and delegation scenarioes. This improves the situation making things more flexible from the current
filter system. It also may allow filters to be simplified to remove the SELF uuid resolve step in some cases.

### Filter based groups

These are groups who's members are dynamicly allocated based on a filter query. This allows a similar
level of dynamic group management as we have currently with access profiles, but with the additional
ability for them to be used outside of the access control context. This is the "bridge" allowing us to
move from filter based access controls to "group" targetted.

A risk of filter based groups is "infinite churn" because of recursion. This can occur if you
had a rule such a "and not memberof = self" on a dynamic group. Because of this, filters on
dynamic groups may not use "memberof" unless they are internally provided by the kanidm project so
that we can vet these rules as correct and without creating infinite recursion scenarioes.

### Access rules extracted to ACI entries on targets

The access control profiles are an excellent way to administer access where you can specific whom
has access to what, but it makes it harder for the reverse query which is "who has access to this
specific entity". Since this is needed for both search and auditing, by specifying our access profiles
in the current manner, but using them to generate ACE rules on the target entry will allow the search
and audit paths to answer the question of "who has access to this entity" much faster.

### Sudo Mode

A flag should exist on a session defining "sudo" mode which requires a special account policy membership
OR a re-authentication to enable. This sudo flag is a time window on a session token which can
allow/disallow certain behaviours. It would be necessary for all write paths to have access to this
value.

### Account Policy

Account policy defines rules on accounts and what they can or can't do with regard to properties and
authentication. This is required for sudo mode so that a group of accounts can be "always in sudo"
mode and this enforces rules on session expiry.

## Access Control Use Cases

### Default Roles / Seperation of Privilege

By default we attempt to seperate privileges so that "no single account" has complete authority
over the system.

Satisfied by:
* Refactor of default access controls
* Filter based groups
* Sudo Mode

#### System Admin

This role, also called "admins" is responsible to manage Kanidm as a service. It does NOT manage
users or accounts.

The "admins" role is responsible to manage:

* The name of the domain
* Configuration of the servers and replication
* Management of external integrations (oauth2)

#### Service Account Admin

The role would be called "sa\_admins" and would be responsible for top level management of service
accounts, and delegating authority for service account administration to managing users.

* Create service accounts
* Delegate service account management to owners groups
* Migrate service accounts to persons

The service account admin is capable of migrating service accounts to persons as it is "yielding"
control of the entity, rather than an idm admin "taking" the entity which may have security impacts.

#### Service Desk

This role manages a subset of persons. The helpdesk roles are precluded from modification of
"higher privilege" roles like service account, identity and system admins. This is due to potential
privilege escalation attacks.

* Can create credential reset links
* Can lock and unlock accounts and their expiry.

#### Idm Admin

This role manages identities, or more specifically person accounts. In addition in is a
"high privilege" service desk role and can manage high privilege users as well.

* Create persons
* Modify and manage persons
* All roles of service desk for all persons

### Self Write / Write Privilege

Currently write privileges are always available to any account post-authentication. Writes should
only be available after an extra "challenge" or "sudo" style extra auth, and only have a limited
time window of usage. The write window can be extended during the session. This allows extremely
long lived sessions contrast to the current short session life. It also makes it safer to provide
higher levels of privilege to persons since these rights are behind a re-authentication event.

Some accounts should always be considered able to write, and these accounts should have limited
authentication sessions as a result of this.

Satisfied by:

* Access profiles target specifiers instead of filters
* Sudo Mode

### Oauth2 Service Read (Nice to Have)

For ux/ui integration, being able to list oauth2 applications that are accessible to the user
would be a good feature. To limit "who" can see the oauth2 applications that an account can access
a way to "allow read" but by proxy of the related users of the oauth2 service. This will require
access controls to be able to interept the oauth2 config and provide rights based on that.

Satisfied by:

* Access profiles target specifiers instead of filters

### Administration

Access controls should be easier to manage and administer, and should be group based rather than
filter based. This will make it easier for administrators to create and define their own access
rules.

* Refactor of default access controls
* Access profiles target specifiers instead of filters
* Filter based groups

### Service Account Access

Service accounts should be able to be "delegated" administration, where a group of users can manage
a service account. This should not require administrators to create unique access controls for each
service account, but a method to allow mapping of the service account to "who manages it".

* Sudo Mode
* Account Policy
* Access profiles target specifiers instead of filters
* Refactor of default access controls

### Auditing of Access

It should be easier to audit whom has access to what by inspecting the entry to view what can access
it.

* Access rules extracted to ACI entries on targets
* Access profiles target specifiers instead of filters


