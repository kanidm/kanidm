
Default IDM Layout
------------------

It's important we have a good default IDM entry layout, as this will serve as
examples and guidance for many users. We also need to consider that the defaults
may be ignored, but many users will consume them by default.

Additionally, we also need to think carefully about the roles and interactions with the
default entries, and how people will deploy and interact with software like this. This document is to discuss the roles and their requirements, rather than the absolute details of the implementation.

Privileged Groups
-----------------

Due to the RBAC design of the system, it's important to consider that some groups will have a large
amount of ability in the server, and should be managed carefully. It is because of this that
groups with a high amount of power will also be a member of the "high access" group. This means
we can target access controls over the high access group, but we can also quickly and easily find
accounts that are members. It may even be possible to audit on addition of "high access" as memberof
to any account.

Initialisation and System Setup
-------------------------------

These are initialised with the normal migrations framework. We must consider that
migrations could remove some admins changes, so we must choose the migration
strategy carefully. There is benefit to acp improvement on upgrade, but also
some deployments may not wish for this.

Security Notes
--------------

In the design of this, I did consider the usage of targetreceiver rules in these defaults
that use the AndNot could create a scenario where someone copies or creates their own
access controls and forgets to include the "high access" exclusion. I think that generally
in the cases where someone is creating their own access controls, they will use stricter targeting
such as directly listing groups, rather than broad accesses like this. I also think that many
people will use these as examples, so it will be visible to copy the require and-not's if needed.

Roles
-----

This is a list of roles/groups and some loose requirements, but also thoughts and justification of
the design and setup.

Users
=====

Users is the class of all accounts that can authenticate. It's important that users by default have
full self-view rights, but also that they have a set of limited self-write rights. An example of
a self write we disallow is changing unix attributes.

* Read to all self attributes (within security constraints).
* Write to a limited set of self attributes, such as name, displayname, legalname, ssh-keys, credentials etc.

Account Managers
================

Account managers are people who are tasked to support and aid with technical interactions of a user
with this system. Classically this would be a service desk who would require this role. Importantly
compared to some other roles, this will need to potentially be able to reset credentials for an
account.

As a result, this is high access. This role importantly should NOT be able to lock or alter
credentials of high access granted accounts. That must be performed by a higher privilege.

* read and write to accounts, including write credentials but NOT private data (see people manager)
* ability to lock and unlock accounts, excluding high access members.


Group Managers
=============

This is a role who is able to manage and create groups on the system. Note this does not include
high access groups. This is intended to be for support (ie service desk) staff to help users
be added to the necessary security groups within reason.

* read all groups
* write group but not high access

Admins
======

These are the people who deploy and manage the server. It's important that they have the ability
to recover the system in DR scenarios, manage the technical implementation and deployment of
the instance, that they can grant privileges to other groups, and they
must bootstrap the initial deployment out of the box.

With this in mind, unlike other systems, admins do not have *unlimited* scope of power and access
by default, but they are able to escalate to have *unlimited* power. This group as a result should
be highly controlled and limited to "need to access" basis, and only providing claims when required.
For the reasons stated, this is considered a "high access" account.

* read and write access control entries.
* read and write schema entries.
* modify all groups including high access groups.
* create new accounts (to bootstrap the system).
* modify high access accounts as an escalation for security sensitive accounts.
* recover from the recycle bin

People Managers
===============

These are the people who require the ability to read or write to private and sensitive data of
peoples accounts. It's important to consider this will become two privileges, one for read, one
for write.

Due to dealing with potentially private or sensitive information, this is a "high access" account.

* read private or sensitive data of persons, IE legalName
* write private or sensitive data of persons, IE legalName

Remember, this role does NOT allow technical changes, IE password changes or normal technical changes.

Anonymous Clients + Everyone Else
=================================

These are clients that do not authenticate to the service, or have authenticated and we need to show
a default set of reasonable public information about the account.
Common examples would be unix servers, applications, idm proxies, email
clients as anonymous users, and all the others listed groups here would be authenticated and require
the basic read capabilities.

As a result, we have to only allow the *minimum* information to be access that is required for those
clients to run. We focus on the unix client anonymous needs in this case, and may add
other anonymous read types later as we understand different applications people choose to deploy
with the system.

* read memberof, unix attrs, name, displayname, class

RADIUS Servers
==============

Radius servers are a special class of application because they need to read security sensitive
credentials from the server. Due to the historical challenges of deploying radius, this role
should exist by default.

Due to the handling of credentials, this is a "high access" group.

* Read radius credentials
* Read other needed attributes to fulfil radius functions.

External Account Systems
========================

External accounts systems generally provide a feed of data to the IDM system to then perform actions
such as account creation, deletion and modification. You could consider a HR system, or even a
web portal for self sign up as this type of system.

As a result, this has some more complex possible interactions. A HR system may need full account
and group management rights including private data modification. Another system could be to
sync from another IDM but only requires non-sensitive data types so may just need group and
other access. Finally, a web portal for a user to self-sign up may only need account creation
rights.

It's important to note, that in this ACI that high access groups should *not* be modifiable.

This is a "high access" role due to the scope for account manipulation and damage if misused.
