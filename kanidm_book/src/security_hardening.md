# Security Hardening

Kanidm ships with a secure-by-default configuration, however that is only as strong
as the platform that Kanidm operates in. This could be your container environment
or your Unix-like system.

This chapter will detail a number of warnings and security practices you should
follow to ensure that Kanidm operates in a secure environment.

The main server is a high-value target for a potential attack, as Kanidm serves as
the authority on identity and authorisation in a network. Compromise of the Kanidm
server is equivalent to a full-network take over, also known as "game over".
<!-- it is good to avoid abbreviations, especially for the benefit of non-native English speakers -->

The unixd resolver is also a high value target as it can be accessed to allow unauthorised
access to a server, to intercept communications to the server, or more. This also must be protected
carefully.

For this reason, Kanidm's components must be protected carefully. Kanidm avoids many classic
attacks by being developed in a memory safe language, but risks still exist.

## Startup Warnings

At startup Kanidm will warn you if the environment it is running in is suspicious or
has risks. For example:

    kanidmd server -c /tmp/server.toml
    WARNING: permissions on /tmp/server.toml may not be secure. Should be readonly to running uid. This could be a security risk ...
    WARNING: /tmp/server.toml has 'everyone' permission bits in the mode. This could be a security risk ...
    WARNING: /tmp/server.toml owned by the current uid, which may allow file permission changes. This could be a security risk ...
    WARNING: permissions on ../insecure/ca.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
    WARNING: permissions on ../insecure/cert.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
    WARNING: permissions on ../insecure/key.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
    WARNING: ../insecure/key.pem has 'everyone' permission bits in the mode. This could be a security risk ...
    WARNING: DB folder /tmp has 'everyone' permission bits in the mode. This could be a security risk ...

Each warning highlights an issue that may exist in your environment. It is not possible for us to
prescribe an exact configuration that may secure your system. This is why we only present
possible risks.

### Should be readonly to running uid

TODO is the running UID the kanidm daemon?

Files such as configurations should be read-only to this UID/GID. If an attacker is
able to gain code execution, they are then unable to modify the configuration to write, or to over-write
files in other locations, or to tamper with the systems configuration.

This can be prevented by changing the files ownership to another user, or removing "write" bits
from the group.

### 'everyone' permission bits in the mode

This means that given a permission mask, "everyone" or all users of the system can read, write or
execute the content of this file. This may mean that if an account on the system is compromised the
attacker can read Kanidm content and may be able to further attack the system as a result.

This can be prevented by removing "everyone: execute bits from parent directories containing the
configuration, and removing "everyone" bits from the files in question.

### owned by the current uid, which may allow file permission changes

File permissions in unix systems are a discrestionary access control system, which means the
named uid owner is able to further modify the access of a file regardless of the current
settings. For example:

    [william@amethyst 12:25] /tmp > touch test
    [william@amethyst 12:25] /tmp > ls -al test
    -rw-r--r--  1 william  wheel  0 29 Jul 12:25 test
    [william@amethyst 12:25] /tmp > chmod 400 test
    [william@amethyst 12:25] /tmp > ls -al test
    -r--------  1 william  wheel  0 29 Jul 12:25 test
    [william@amethyst 12:25] /tmp > chmod 644 test
    [william@amethyst 12:26] /tmp > ls -al test
    -rw-r--r--  1 william  wheel  0 29 Jul 12:25 test

Notice that even though the file was set to "read only" to william, and no permission to any
other users, user "william" can change the bits to add write permissions back or permissions
for other users.
<!-- gotta watch out for that william dude, he is trouble -->

This can be prevent by making the file owner a different UID than the running process for kanidm.

### A secure example

Between these three issues it can be hard to see a possible strategy to secure files, however
one way exists - group read permissions. The most effective method to secure resources for kanidm
is to set configurations to:

    [william@amethyst 12:26] /etc/kanidm > ls -al server.toml
    -r--r-----   1 root           kanidm      212 28 Jul 16:53 server.toml

The kanidm server should be run as "kanidm:kanidm" with the appropriate user and user private
group created on your system. This applies to unixd configuration as well.

TODO is the kanidm user created the same way as other daemon users, without a /home dir and 
no shell access (/sbin/nologin, /bin/false)?

For the database your data folder should be:

    [root@amethyst 12:38] /data/kanidm > ls -al .
    total 1064
    drwxrwx---   3 root     kanidm      96 29 Jul 12:38 .
    -rw-r-----   1 kanidm   kanidm  544768 29 Jul 12:38 kanidm.db

This means 770 root:kanidm. This allows kanidm to create new files in the folder, but prevents
kanidm from being able to change the permissions of the folder. Because the folder does not have
"everyone" mode bits, the content of the database is secure because users can now cd/read
from the directory.

Configurations for clients, such as /etc/kanidm/config, should be secured with read-only permissions:

    [william@amethyst 12:26] /etc/kanidm > ls -al config
    -r--r--r--    1 root  wheel    38 10 Jul 10:10 config
    
TODO must it be the wheel group? the wheel group controls sudo users on many linuxes    

This file should be "everyone"-readable, which is why the bits are defined as such.

> NOTE: Why do you use 440 or 444 modes?
>
> A bug exists in the implementation of readonly() in rust that checks this as "does a write
> bit exist for any user" vs "can the current uid write the file?". This distinction is subtle
> but it affects the check. We don't believe this is a significant issue though because
> setting these to 440 and 444 helps to prevent accidental changes by an administrator anyway

## Running as non-root in docker

The commands provided in this book will run kanidmd as "root" in the container to make the onboarding
smoother. However, this is not recommended in production for security reasons.

You should allocate unique uid and gid numbers for the service to run as on your host
system. In this example we use `1000:1000`

You will need to adjust the permissions on the `/data` volume to ensure that the process
can manage the files. Kanidm requires the ability to write to the `/data` directory to create
the sqlite files. This uid/gid number should match the above. You could consider the following
changes to help isolate these changes:

    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh
    mkdir /data/db/
    chown 1000:1000 /data/db/
    chmod 750 /data/db/
    sed -i -e "s/db_path.*/db_path = \"\/data\/db\/kanidm.db\"/g" /data/server.toml
    chown root:root /data/server.toml
    chmod 644 /data/server.toml
    
    <!-- removed prompts for consistency with other command examples -->

You can then use this to run the kanidm server in docker with a user:

    docker run --rm -i -t -u 1000:1000 -v kanidmd:/data kanidm/server:latest /sbin/kanidmd ...

> **HINT**
> You need to use the uid number/gid number with the `-u` argument, as the container can't resolve
> usernames from the host system.