# Posix Accounts and Groups

Kanidm has features that enable it's accounts and groups to be consumed on
posix like machines, such as Linux, FreeBSD, or others.

## Notes on Posix Features

There are a number of design decisions that have been made in the posix features
of kanidm that are intended to make distributed systems easier to manage, and
client systems more secure.

### Uid and Gid numbers

In Kanidm there is no difference between a uid and a gid number. On most unix systems
a user will create all files with a primary user and group. The primary group is
effectively equivalent to the permissions of the user. It is very easy to see scenarioes
where someone may change the account to have a shared primary group (ie allusers),
but without change the umask all client systems. This can cause user's data to be
compromised by any member of the same shared group.

To prevent this many system create a user private group, or UPG. This group has the
gid number match the uid number of the user, and the user set's it's primary
group id to the gid number of the UPG.

As there is now an equivalence between the uid and gid number of the user and the UPG,
there is no benefit to seperating these values. As a result kanidm accounts *only*
have a gidnumber, which is also considered to be it's uidnumber as well. This has a benefit
of preventing accidental creation of a separate group that has an overlapping gidnumber
(the uniqueness attribute of the schema will block the creation).

### UPG generation

Due to the requirement that a user have a UPG for security, many systems create these as
two independent items. For example in /etc/passwd and /etc/group

    # passwd
    william:x:654401105:654401105::/home/william:/bin/zsh
    # group
    william:x:654401105:

Other systems like FreeIPA use a plugin that generates a UPG as a database record on
creation of the account.

Kanidm does neither of these. As the gidnumber of the user must by unique, and a user
implies the UPG must exist, we are able to generate UPG's on demand from the account.
This has a single side effect, which is that you are unable to add any members to a
UPG - however, given the nature of a user private group, this is somewhat the point.

### Gid number generation

In the future Kanidm plans to have async replication as a feature between writable
database servers. In this case we need to be able to allocate stable and reliable
gidnumbers to accounts on replicas that may not be in continual communication.

To do this, we use the last 32 bits of the account or group's UUID to generate the
gidnumber.

A valid concern is possibility of duplication in the lower 32 bits. Given the
birthday problem, if you have 77,000 groups and accounts, you have a 50% chance
of duplication. With 50,000 you have 20% chance, 9,300 you have a 1% chance and
with 2900 you have 0.1% chance.

We advise that if you have a site with >10,000 users you should use an external system
to allocate gidnumbers serially or in a consistent manner to avoid potential duplication
events.

This design decision is made as most small sites will benefit greatly from the
autoallocation policy and the simplicity of it's design, while larger enterprises
will already have IDM or Business process applications for HR/People that are
capable of suppling this kind of data in batch jobs.

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
special or seperate type of membership for posix members required.
