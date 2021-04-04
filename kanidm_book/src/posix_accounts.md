# POSIX Accounts and Groups

Kanidm has features that enable its accounts and groups to be consumed on
POSIX-like machines, such as Linux, FreeBSD, or others.

## Notes on POSIX Features

Many design decisions have been made in the POSIX features
of kanidm that are intended to make distributed systems easier to manage and
client systems more secure.

### UID and GID numbers

In Kanidm there is no difference between a UID and a GID number. On most UNIX systems
a user will create all files with a primary user and group. The primary group is
effectively equivalent to the permissions of the user. It is very easy to see scenarios
where someone may change the account to have a shared primary group (ie `allusers`),
but without changing the umask on all client systems. This can cause users' data to be
compromised by any member of the same shared group.

To prevent this, many systems create a "user private group", or UPG. This group has the
gidnumber matching the uidnumber of the user, and the user sets its primary
group id to the gidnumber of the UPG.

As there is now an equivalence between the UID and GID number of the user and the UPG,
there is no benefit to separating these values. As a result kanidm accounts *only*
have a gidnumber, which is also considered to be its uidnumber as well. This has the benefit
of preventing the accidental creation of a separate group that has an overlapping gidnumber
(the `uniqueness` attribute of the schema will block the creation).

### UPG generation

Due to the requirement that a user have a UPG for security, many systems create these as
two independent items. For example in /etc/passwd and /etc/group

    # passwd
    william:x:654401105:654401105::/home/william:/bin/zsh
    # group
    william:x:654401105:

Other systems like FreeIPA use a plugin that generates a UPG as a database record on
creation of the account.

Kanidm does neither of these. As the gidnumber of the user must be unique, and a user
implies the UPG must exist, we can generate UPG's on-demand from the account.
This has a single side effect - that you are unable to add any members to a
UPG - given the nature of a user private group, this is the point.

### gidnumber generation

In the future, Kanidm plans to have asynchronous replication as a feature between writable
database servers. In this case, we need to be able to allocate stable and reliable
gidnumbers to accounts on replicas that may not be in continual communication.

To do this, we use the last 32 bits of the account or group's UUID to generate the
gidnumber.

A valid concern is the possibility of duplication in the lower 32 bits. Given the
birthday problem, if you have 77,000 groups and accounts, you have a 50% chance
of duplication. With 50,000 you have a 20% chance, 9,300 you have a 1% chance and
with 2900 you have a 0.1% chance.

We advise that if you have a site with >10,000 users you should use an external system 
to allocate gidnumbers serially or consistently to avoid potential duplication events.

This design decision is made as most small sites will benefit greatly from the
autoallocation policy and the simplicity of its design, while larger enterprises
will already have IDM or Business process applications for HR/People that are
capable of supplying this kind of data in batch jobs.

## Enabling Posix Attributes on Accounts

To enable posix account features and ids on an account, you require the permission `idm_account_unix_extend_priv`.
This is provided to `idm_admins` in the default database.

You can then use the following command to enable posix extensions.

    kanidm account posix set --name idm_admin <account_id> [--shell SHELL --gidnumber GID]
    kanidm account posix set --name idm_admin demo_user
    kanidm account posix set --name idm_admin demo_user --shell /bin/zsh
    kanidm account posix set --name idm_admin demo_user --gidnumber 2001

You can view the accounts posix token details with:

    kanidm account posix show --name anonymous demo_user

## Enabling Posix Attributes on Groups

To enable posix group features and ids on an account, you require the permission `idm_group_unix_extend_priv`.
This is provided to `idm_admins` in the default database.

You can then use the following command to enable posix extensions.

    kanidm group posix set --name idm_admin <group_id> [--gidnumber GID]
    kanidm group posix set --name idm_admin demo_group
    kanidm group posix set --name idm_admin demo_group --gidnumber 2001

You can view the accounts posix token details with:

    kanidm group posix show --name anonymous demo_group

Posix enabled groups will supply their members as posix members to clients. There is no
special or separate type of membership for posix members required.