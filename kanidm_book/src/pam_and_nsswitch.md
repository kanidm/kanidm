# Pam and nsswitch

Pam and nsswitch are the core mechanisms used by Linux and Bsd clients
to resolve identities from an IDM service like kanidm into accounts that
can be used on the machine for various interactive tasks.

## The unix daemon

Kanidm provide a unix daemon that runs on any client that wants to use pam
and nsswitch integration. This is provided as the daemon can cache the accounts
for users who have unreliable networks or leave the site where kanidm is. The
cache is also able to cache missing-entry responses to reduce network traffic
and main server load.
Additionally, the daemon means that the pam and nsswitch integration libraries
can be small, helping to reduce the attack surface of the machine.
Similar, a tasks daemon is also provided that can create home directories on first
login, and supports a number of features related to aliases and links to these
home directories.

We recommend you install the client daemon from your system package manager.

    # OpenSUSE
    zypper in kanidm-unixd-clients
    # Fedora
    dnf install kanidm-unixd-clients

You can check the daemon is running on your Linux system with

    systemctl status kanidm_unixd

You can check the privileged tasks daemon is running with

    systemctl status kanidm_unixd_tasks

> **NOTE** The `kanidm_unixd_tasks` daemon is not required for pam and nsswitch functionality.
> If disabled, your system will function as usual. It is however recommended due to the features
> it provides supporting kanidm's capabilities.

Both unixd daemons use the connection configuration from /etc/kanidm/config. This is the covered in
client_tools. You can also configure some details of the unixd daemons in /etc/kanidm/unixd.

    pam_allowed_login_groups = ["posix_group"]
    default_shell = "/bin/bash"
    home_prefix = "/home/"
    home_attr = "uuid"
    home_alias = "spn"
    uid_attr_map = "spn"
    gid_attr_map = "spn"

The `pam_allowed_login_groups` defines a set of posix groups where membership of any of these
groups will be allowed to login via pam. All posix users and groups can be resolved by nss
regardless of pam login status. This may be a group name, spn or uuid.

`default_shell` is the default shell for users with none defined. Defaults to /bin/bash.

`home_prefix` is the prepended path to where home directories are stored. Must end with
a trailing `/`. Defaults to `/home/`.

`home_attr` is the default token attribute used for the home directory path. Valid
choices are `uuid`, `name`, `spn`. Defaults to `uuid`.

`home_alias` is the default token attribute used for generating symlinks pointing to the users
home directory. If set, this will become the value of the home path
to nss calls. It is recommended you choose a "human friendly" attribute here.
Valid choices are `none`, `uuid`, `name`, `spn`. Defaults to `spn`.

> **NOTICE:**
> All users in kanidm can change their name (and their spn) at any time. If you change
> `home_attr` from `uuid` you *must* have a plan on how to manage these directory renames
> in your system. We recommend that you have a stable id (like the uuid) and symlinks
> from the name to the uuid folder. Automatic support is provided for this via the unixd
> tasks daemon, as documented here.

`uid_attr_map` chooses which attribute is used for domain local users in presentation. Defaults
to `spn`. Users from a trust will always use spn.

`gid_attr_map` chooses which attribute is used for domain local groups in presentation. Defaults
to `spn`. Groups from a trust will always use spn.

You can then check the communication status of the daemon as any user account.

    $ kanidm_unixd_status

If the daemon is working, you should see:

    [2020-02-14T05:58:37Z INFO  kanidm_unixd_status] working!

If it is not working, you will see an error message:

    [2020-02-14T05:58:10Z ERROR kanidm_unixd_status] Error -> Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }

For more, see troubleshooting.

## nsswitch

When the daemon is running you can add the nsswitch libraries to /etc/nsswitch.conf

    passwd: compat kanidm
    group: compat kanidm

You can then test that a posix extended user is able to be resolved with:

    $ getent passwd <account name>
    $ getent passwd testunix
    testunix:x:3524161420:3524161420:testunix:/home/testunix:/bin/bash

You can also do the same for groups.

    $ getent group <group name>
    $ getent group testgroup
    testgroup:x:2439676479:testunix

## PAM

> **WARNING:** Modifications to pam configuration *may* leave your system in a state
> where you are unable to login or authenticate. You should always have a recovery
> shell open while making changes (ie root), or have access to single-user mode
> at the machines console.

PAM (Pluggable Authentication Modules) is how a unix like system allows users to authenticate
and be authorised to start interactive sessions. This is configured through a stack of modules
that are executed in order to evaluate the request. This is done through a series of steps
where each module may request or reused authentication token information.

### Before you start

You *should* backup your /etc/pam.d directory from it's original state as you *may* change the
pam config in a way that will cause you to be unable to authenticate to your machine.

    cp -a /etc/pam.d /root/pam.d.backup

### SUSE

To configure PAM on suse you must module four files:

    /etc/pam.d/common-account
    /etc/pam.d/common-auth
    /etc/pam.d/common-password
    /etc/pam.d/common-session

Each of these controls one of the four stages of pam. The content should look like:

    # /etc/pam.d/common-account-pc
    account    [default=1 ignore=ignore success=ok] pam_localuser.so
    account    required    pam_unix.so
    account    required    pam_kanidm.so ignore_unknown_user

    # /etc/pam.d/common-auth-pc
    auth        required      pam_env.so
    auth        [default=1 ignore=ignore success=ok] pam_localuser.so
    auth        sufficient    pam_unix.so nullok try_first_pass
    auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
    auth        sufficient    pam_kanidm.so debug ignore_unknown_user
    auth        required      pam_deny.so

    # /etc/pam.d/common-password-pc
    password    requisite   pam_cracklib.so
    password    [default=1 ignore=ignore success=ok] pam_localuser.so
    password    required    pam_unix.so use_authtok nullok shadow try_first_pass
    password    required    pam_kanidm.so

    # /etc/pam.d/common-session-pc
    session optional    pam_systemd.so
    session required    pam_limits.so
    session optional    pam_unix.so try_first_pass
    session optional    pam_kanidm.so
    session optional    pam_umask.so
    session optional    pam_env.so

> **WARNING:** Ensure that `pam_mkhomedir` or `pam_oddjobd` are *not* present in your pam configuration
> these interfer with the correct operation of the kanidm tasks daemon.

### Fedora

TBD

## Troubleshooting

### Increase logging

For the unixd daemon, you can increase the logging with:

    systemctl edit kanidm-unixd.service

And add the lines:

    [Service]
    Environment="RUST_LOG=kanidm=debug"

Then restart the kanidm-unixd.service.

The same pattern is true for the kanidm-unixd-tasks.service daemon.

To debug the pam module interactions add `debug` to the module arguments such as:

    auth sufficient pam_kanidm.so debug

### Check the socket permissions

Check that the /var/run/kanidm-unixd/sock is 777, and that non-root readers can see it with
ls or other tools.

Ensure that /var/run/kanidm-unixd/task_sock is 700, and that it is owned by the kanidm unixd
process user.

### Check you can access the kanidm server

You can check this with the client tools:

    kanidm self whoami --name anonymous

### Ensure the libraries are correct.

You should have:

    /usr/lib64/libnss_kanidm.so.2

### Increase connection timeout

In some high latency environments, you may need to increase the connection timeout. We set
this low to improve response on LANs, but over the internet this may need to be increased.
By increasing the conn timeout, you will be able to operate on higher latency links, but
some operations may take longer to complete causing a degree of latency. By increasing the
cache_timeout, you will need to refresh "less" but it may mean on an account lockout or
group change, that you need up to cache_timeout to see the effect (this has security
implications)

    # /etc/kanidm/unixd
    # Seconds
    conn_timeout = 8
    # Cache timeout
    cache_timeout = 60

### Invalidate the cache

You can invalidate the kanidm_unixd cache with:

    $ kanidm_cache_invalidate

You can clear (wipe) the cache with:

    $ kanidm_cache_clear

There is an important distinction between these two - invalidate cache items may still
be yielded to a client request if the communication to the main kanidm server is not
possible. For example, you may have your laptop in a park without wifi.

Clearing the cache however, completely wipes all local data about all accounts and groups.
If you are relying on this cached (but invalid data) you may lose access to your accounts until
other communication issues have been resolved.

