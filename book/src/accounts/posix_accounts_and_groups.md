# POSIX Accounts and Groups

Kanidm has features that enable its accounts and groups to be consumed on POSIX-like machines, such as Linux, FreeBSD or
others. Both service accounts and person accounts can be used on POSIX systems.

## Notes on POSIX Features

Many design decisions have been made in the POSIX features of Kanidm that are intended to make distributed systems
easier to manage and client systems more secure.

### UID and GID Numbers

In Kanidm there is no difference between a UID and a GID number. On most UNIX systems a user will create all files with
a primary user and group. The primary group is effectively equivalent to the permissions of the user. It is very easy to
see scenarios where someone may change the account to have a shared primary group (ie `allusers`), but without changing
the umask on all client systems. This can cause users' data to be compromised by any member of the same shared group.

To prevent this, many systems create a "user private group", or UPG. This group has the GID number matching the UID of
the user, and the user sets their primary group ID to the GID number of the UPG.

As there is now an equivalence between the UID and GID number of the user and the UPG, there is no benefit in separating
these values. As a result Kanidm accounts _only_ have a GID number, which is also considered to be its UID number as
well. This has the benefit of preventing the accidental creation of a separate group that has an overlapping GID number
(the `uniqueness` attribute of the schema will block the creation).

### UPG Generation

Due to the requirement that a user have a UPG for security, many systems create these as two independent items. For
example, in /etc/passwd and /etc/group:

```text
# passwd
william:x:654401105:654401105::/home/william:/bin/zsh
# group
william:x:654401105:
```

Other systems like FreeIPA use a plugin that generates a UPG as a separate group entry on creation of the account. This
means there are two entries for an account, and they must be kept in lock-step. This poses a risk of desynchronisation
that can and will happen on these systems leading to possible issues.

Kanidm does neither of these. As the GID number of the user must be unique, and a user implies the UPG must exist, we
can generate UPG's on-demand from the account. This has an important side effect - that you are unable to add any
members to a UPG - given the nature of a user private group, this is the point.

### GID Number Generation

Kanidm has asynchronous replication as a feature between database servers. In this case, we need to be able to allocate
stable and reliable GID numbers to accounts on replicas that may not be in continual communication.

To do this, we use the last 24 bits of the account or group's UUID to generate the GID number. We can only use the UID
range `1879048192` (`0x70000000`) to `2147483647` (`0x7fffffff`) due to limitations of the Linux kernel and
[systemd reserving other uids in the range](http://systemd.io/UIDS-GIDS/) for its exclusive use.

| name             | min        | max        |
| ---------------- | ---------- | ---------- |
| system           | 0          | 999        |
| user             | 1000       | 60000      |
| systemd homed    | 60001      | 60577      |
| unused A         | 60578      | 61183      |
| systemd dynuser  | 61184      | 65519      |
| unused B         | 65520      | 65533      |
| nobody           | 65534      | 65534      |
| 16bit limit      | 65535      | 65535      |
| unused C         | 65536      | 524287     |
| systemd nspawn   | 524288     | 1879048191 |
| kanidm dyn alloc | 1879048192 | 2147483647 |
| unusable         | 2147483648 | 4294967295 |

A valid concern is the possibility of duplication in the lower 24 bits. Given the
[birthday problem](https://en.wikipedia.org/wiki/Birthday_problem), if you have ~7700 groups and accounts, you have a
50% chance of duplication. With ~5000 you have a 25% chance, ~930 you have a 1% chance and with 290 you have a 0.1%
chance.

We advise that if you have a site with greater than approximately 2,000 users you should use an external system to
allocate GID numbers serially or consistently to avoid potential duplication events.

We recommend the use of the range `65536` through `524287` (`unused C`) for manual allocation. This leaves the range
`1000` through `65535` for OS/Distro purposes, and allows Kanidm to continue dynamic allocation in the range
`1879048192` to `2147483647` if you choose a hybrid allocation approach.

This design decision is made as most small sites will benefit greatly from the auto-allocation policy and the simplicity
of its design, while larger enterprises will already have IDM or business process applications for HR/People that are
capable of supplying this kind of data in batch jobs.

## Enabling POSIX Attributes

### Enabling POSIX Attributes on Accounts

To enable POSIX account features and IDs on an account, you require the permission `idm_unix_admins`. This is provided
to `idm_admins` by default.

You can then use the following command to enable POSIX extensions on a person or service account.

```bash
kanidm [person OR service-account] posix set --name idm_admin <account_id> [--shell SHELL --gidnumber GID]

kanidm person posix set --name idm_admin demo_user
kanidm person posix set --name idm_admin demo_user --shell /bin/zsh
kanidm person posix set --name idm_admin demo_user --gidnumber 2001

kanidm service-account posix set --name idm_admin demo_account
kanidm service-account posix set --name idm_admin demo_account --shell /bin/zsh
kanidm service-account posix set --name idm_admin demo_account --gidnumber 2001
```

You can view the accounts POSIX token details with:

```bash
kanidm person posix show --name anonymous demo_user
kanidm service-account posix show --name anonymous demo_account
```

### Enabling POSIX Attributes on Groups

To enable POSIX group features and IDs on an account, you require the permission `idm_unix_admins`. This is provided to
`idm_admins` by default.

You can then use the following command to enable POSIX extensions:

```bash
kanidm group posix set --name idm_admin <group_id> [--gidnumber GID]
kanidm group posix set --name idm_admin demo_group
kanidm group posix set --name idm_admin demo_group --gidnumber 2001
```

You can view the accounts POSIX token details with:

```bash
kanidm group posix show --name anonymous demo_group
```

POSIX-enabled groups will supply their members as POSIX members to clients. There is no special or separate type of
membership for POSIX members required.

## Troubleshooting Common Issues

### subuid conflicts with Podman

Due to the way that Podman operates, in some cases using the Kanidm client inside non-root containers with Kanidm
accounts may fail with an error such as:

```text
ERROR[0000] cannot find UID/GID for user NAME: No subuid ranges found for user "NAME" in /etc/subuid
```

This is a fault in Podman and how it attempts to provide non-root containers, when UID/GIDs are greater than 65535. In
this case, you may manually allocate your users GID number to be between 1000 - 65535, which may not trigger the fault.
