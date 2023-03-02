
gid number generation
---------------------

Gid number generation helps to ease admin burden for posix accounts by dynamically allocating
the gidnumbers on accounts in a way that is distributed and safe for a multi-write server
environment.

Allocation Algorithm
--------------------

As each entry has a UUID which is a 128 bit random identifier, we can use this for our gid number
by extracting the last 32 bits.

Why only gid number?
--------------------

It's a common misconception that uid is the only separation on linux that matters. When a user
account exists, it has a primary user id AND a primary group id. Default umask grants rw to any
member of the same primary group id, which leads to misconfigurations where an admin in the intent
of saying "all users belong to default_users" ends up granting all users the right to read and write
all other users folders.

Additionally, there are rights around process and ptrace that exist for the same gid as well.

In this way, uid and primary gid of a user MUST be unique to the user, and many systems (like
SSSD's dynamic gid allocation from AD and FreeIPA) make effort to assign a user-private-group
to combat this issue.

Instead of creating a group per account, we instead *imply* that the gidnumber *is* the uidnumber,
and that a posixaccount *implies* the existence of a user private group that the pam/nsswitch
tools will generate on the client. This also guarantees that posixgroups will never conflict or
overlap with the uid namespace with weth attr uniqueness plugin.

