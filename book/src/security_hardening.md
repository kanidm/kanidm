# Security Hardening

Kanidm ships with a secure-by-default configuration, however that is only as strong as the
environment that Kanidm operates in. This means the security of your container environment and
server is extremely important when running Kanidm.

This chapter will detail a number of warnings and security practices you should follow to ensure
that Kanidm operates in a secure environment.

The main server is a high-value target for a potential attack, as Kanidm serves as the authority on
identity and authorisation in a network. Compromise of the Kanidm server is equivalent to a
full-network take over, also known as "game over".

The unixd resolver is also a high value target as it can be accessed to allow unauthorised access to
a server, to intercept communications to the server, or more. This also must be protected carefully.

For this reason, Kanidm's components must be secured and audited. Kanidm avoids many classic attacks
by being developed in a memory safe language, but risks still exist in the operating environment.

## Startup Warnings

At startup Kanidm will warn you if the environment it is running in is suspicious or has risks. For
example:

```bash
kanidmd server -c /tmp/server.toml
WARNING: permissions on /tmp/server.toml may not be secure. Should be readonly to running uid. This could be a security risk ...
WARNING: /tmp/server.toml has 'everyone' permission bits in the mode. This could be a security risk ...
WARNING: /tmp/server.toml owned by the current uid, which may allow file permission changes. This could be a security risk ...
WARNING: permissions on ../insecure/ca.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
WARNING: permissions on ../insecure/cert.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
WARNING: permissions on ../insecure/key.pem may not be secure. Should be readonly to running uid. This could be a security risk ...
WARNING: ../insecure/key.pem has 'everyone' permission bits in the mode. This could be a security risk ...
WARNING: DB folder /tmp has 'everyone' permission bits in the mode. This could be a security risk ...
```

Each warning highlights an issue that may exist in your environment. It is not possible for us to
prescribe an exact configuration that may secure your system. This is why we only present possible
risks and you must make informed decisions on how to resolve them.

### Should be Read-only to Running UID

Files, such as configuration files, should be read-only to the UID of the Kanidm daemon. If an
attacker is able to gain code execution, they are then unable to modify the configuration to write,
or to over-write files in other locations, or to tamper with the systems configuration.

This can be prevented by changing the files ownership to another user, or removing "write" bits from
the group.

### 'everyone' Permission Bits in the Mode

This means that given a permission mask, "everyone" or all users of the system can read, write or
execute the content of this file. This may mean that if an account on the system is compromised the
attacker can read Kanidm content and may be able to further attack the system as a result.

This can be prevented by removing "everyone: execute bits from parent directories containing the
configuration, and removing "everyone" bits from the files in question.

### Owned by the Current UID, Which May Allow File Permission Changes

File permissions in UNIX systems are a discretionary access control system, which means the named
UID owner is able to further modify the access of a file regardless of the current settings. For
example:

```bash
[william@amethyst 12:25] /tmp > touch test
[william@amethyst 12:25] /tmp > ls -al test
-rw-r--r--  1 william  wheel  0 29 Jul 12:25 test
[william@amethyst 12:25] /tmp > chmod 400 test
[william@amethyst 12:25] /tmp > ls -al test
-r--------  1 william  wheel  0 29 Jul 12:25 test
[william@amethyst 12:25] /tmp > chmod 644 test
[william@amethyst 12:26] /tmp > ls -al test
-rw-r--r--  1 william  wheel  0 29 Jul 12:25 test
```

Notice that even though the file was set to "read only" to william, and no permission to any other
users, user "william" can change the bits to add write permissions back or permissions for other
users.

This can be prevent by making the file owner a different UID than the running process for kanidm.

### A Secure Example

Between these three issues it can be hard to see a possible strategy to secure files, however one
way exists - group read permissions. The most effective method to secure resources for Kanidm is to
set configurations to:

```bash
[william@amethyst 12:26] /etc/kanidm > ls -al server.toml
-r--r-----   1 root           kanidm      212 28 Jul 16:53 server.toml
```

The Kanidm server should be run as "kanidm:kanidm" with the appropriate user and user private group
created on your system. This applies to unixd configuration as well.

For the database your data folder should be:

```bash
[root@amethyst 12:38] /data/kanidm > ls -al .
total 1064
drwxrwx---   3 root     kanidm      96 29 Jul 12:38 .
-rw-r-----   1 kanidm   kanidm  544768 29 Jul 12:38 kanidm.db
```

This means 770 root:kanidm. This allows Kanidm to create new files in the folder, but prevents
Kanidm from being able to change the permissions of the folder. Because the folder does not have
"everyone" mode bits, the content of the database is secure because users can now cd/read from the
directory.

Configurations for clients, such as /etc/kanidm/config, should be secured with read-only permissions
and owned by root:

```bash
[william@amethyst 12:26] /etc/kanidm > ls -al config
-r--r--r--    1 root  root    38 10 Jul 10:10 config
```

This file should be "everyone"-readable, which is why the bits are defined as such.

## Running as Non-root in docker

The commands provided in this book will run kanidmd as "root" in the container to make the
onboarding smoother. However, this is not recommended in production for security reasons.

You should allocate unique UID and GID numbers for the service to run as on your host system. In
this example we use `1000:1000`

You will need to adjust the permissions on the `/data` volume to ensure that the process can manage
the files. Kanidm requires the ability to write to the `/data` directory to create the database
files. This UID/GID number should match the above. You could consider the following changes to help
isolate these changes:

```bash
docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh
mkdir /data/db/
chown 1000:1000 /data/db/
chmod 750 /data/db/
sed -i -e "s/db_path.*/db_path = \"\/data\/db\/kanidm.db\"/g" /data/server.toml
chown root:root /data/server.toml
chmod 644 /data/server.toml
```

Note that the example commands all run inside the docker container.

You can then use this to run the Kanidm server in docker with a user:

```bash
docker run --rm -i -t -u 1000:1000 -v kanidmd:/data kanidm/server:latest /sbin/kanidmd ...
```

> **HINT** You need to use the UID or GID number with the `-u` argument, as the container can't
> resolve usernames from the host system.

## Minimum TLS key lengths

We enforce a minimum RSA and ECDSA key sizes. If your key is insufficently large, the server will
refuse to start and inform you of this.

Currently accepted key sizes are minimum 2048 bit RSA and 224 bit ECDSA.
