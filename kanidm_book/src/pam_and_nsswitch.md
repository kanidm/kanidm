# PAM and nsswitch

[PAM](http://linux-pam.org) and [nsswitch](https://en.wikipedia.org/wiki/Name_Service_Switch) are the core mechanisms used by Linux and BSD clients to resolve identities from an IDM service like Kanidm into accounts that can be used on the machine for various interactive tasks.

## The UNIX daemon

Kanidm provides a UNIX daemon that runs on any client that wants to use PAM and nsswitch integration. This is provided as the daemon can cache the accounts for users who have unreliable networks or leave the site where Kanidm is. The cache is also able to cache missing-entry responses to reduce network traffic and main server load.

Additionally, the daemon means that the PAM and nsswitch integration libraries can be small, helping to reduce the attack surface of the machine. Similarly, a tasks daemon is available that can create home directories on first login and supports several features related to aliases and links to these home directories.

We recommend you install the client daemon from your system package manager.

    # OpenSUSE
    zypper in kanidm-unixd-clients
    # Fedora
    dnf install kanidm-unixd-clients

You can check the daemon is running on your Linux system with

    systemctl status kanidm-unixd

You can check the privileged tasks daemon is running with

    systemctl status kanidm-unixd-tasks

> **NOTE** The `kanidm_unixd_tasks` daemon is not required for PAM and nsswitch functionality.
> If disabled, your system will function as usual. It is however recommended due to the features
> it provides supporting Kanidm's capabilities.

Both unixd daemons use the connection configuration from /etc/kanidm/config. This is the covered in
[client_tools](./client_tools.md#kandim-configuration). 

You can also configure some unixd specific options with the file /etc/kanidm/unixd.

    pam_allowed_login_groups = ["posix_group"]
    default_shell = "/bin/sh"
    home_prefix = "/home/"
    home_attr = "uuid"
    home_alias = "spn"
    uid_attr_map = "spn"
    gid_attr_map = "spn"

The `pam_allowed_login_groups` defines a set of posix groups where membership of any of these
groups will be allowed to login via PAM. All posix users and groups can be resolved by nss
regardless of PAM login status. This may be a group name, spn or uuid.

`default_shell` is the default shell for users with none defined. Defaults to `/bin/sh`.

`home_prefix` is the prepended path to where home directories are stored. Must end with
a trailing `/`. Defaults to `/home/`.

`home_attr` is the default token attribute used for the home directory path. Valid
choices are `uuid`, `name`, `spn`. Defaults to `uuid`.

`home_alias` is the default token attribute used for generating symlinks pointing to the users
home directory. If set, this will become the value of the home path
to nss calls. It is recommended you choose a "human friendly" attribute here.
Valid choices are `none`, `uuid`, `name`, `spn`. Defaults to `spn`.

> **NOTICE:**
> All users in Kanidm can change their name (and their spn) at any time. If you change
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

You can [create a user](./accounts_and_groups.md#creating-accounts) then [enable posix feature on the user](./posix_accounts.md#enabling-posix-attributes-on-accounts).

You can then test that the posix extended user is able to be resolved with:

    $ getent passwd <account name>
    $ getent passwd testunix
    testunix:x:3524161420:3524161420:testunix:/home/testunix:/bin/sh

You can also do the same for groups.

    $ getent group <group name>
    $ getent group testgroup
    testgroup:x:2439676479:testunix

> **HINT** Remember to also create unix password with something like 
> `kanidm account posix set_password --name idm_admin demo_user`. 
> Otherwise there will be no credential for the account to authenticate. 
 
## PAM

> **WARNING:** Modifications to PAM configuration *may* leave your system in a state
> where you are unable to login or authenticate. You should always have a recovery
> shell open while making changes (ie root), or have access to single-user mode
> at the machine's console.

PAM (Pluggable Authentication Modules) is how a unix-like system allows users to authenticate
and be authorised to start interactive sessions. This is configured through a stack of modules
that are executed in order to evaluate the request. This is done through a series of steps
where each module may request or reuse authentication token information.

### Before you start

You *should* backup your /etc/pam.d directory from its original state as you *may* change the
PAM config in a way that will cause you to be unable to authenticate to your machine.

    cp -a /etc/pam.d /root/pam.d.backup

### SUSE / OpenSUSE

To configure PAM on suse you must modify four files, which control the various stages of authentication.

    /etc/pam.d/common-account
    /etc/pam.d/common-auth
    /etc/pam.d/common-password
    /etc/pam.d/common-session

> **IMPORTANT** By default these files are symlinks to their corresponding `-pc` file, for example
> `common-account -> common-account-pc`. If you directly edit these you are updating the inner
> content of the `-pc` file and it WILL be reset on a future upgrade. To prevent this you must
> first copy the `-pc` files. You can then edit the files safely.

    cp /etc/pam.d/common-account-pc  /etc/pam.d/common-account
    cp /etc/pam.d/common-auth-pc     /etc/pam.d/common-auth
    cp /etc/pam.d/common-password-pc /etc/pam.d/common-password
    cp /etc/pam.d/common-session-pc  /etc/pam.d/common-session

The content should look like:

    # /etc/pam.d/common-auth-pc
    # Controls authentication to this system (verification of credentials)
    auth        required      pam_env.so
    auth        [default=1 ignore=ignore success=ok] pam_localuser.so
    auth        sufficient    pam_unix.so nullok try_first_pass
    auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
    auth        sufficient    pam_kanidm.so ignore_unknown_user
    auth        required      pam_deny.so

    # /etc/pam.d/common-account-pc
    # Controls authorisation to this system (who may login)
    account    [default=1 ignore=ignore success=ok] pam_localuser.so
    account    sufficient  pam_unix.so
    account    [default=1 ignore=ignore success=ok]  pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
    account    sufficient    pam_kanidm.so ignore_unknown_user
    account    pam_deny.so

    # /etc/pam.d/common-password-pc
    # Controls flow of what happens when a user invokes the passwd command. Currently does NOT
    # interact with kanidm.
    password    [default=1 ignore=ignore success=ok] pam_localuser.so
    password    required    pam_unix.so use_authtok nullok shadow try_first_pass
    password    [default=1 ignore=ignore success=ok]  pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
    password    required    pam_kanidm.so

    # /etc/pam.d/common-session-pc
    # Controls setup of the user session once a successful authentication and authorisation has
    # occured.
    session optional    pam_systemd.so
    session required    pam_limits.so
    session optional    pam_unix.so try_first_pass
    session optional    pam_umask.so
    session [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
    session optional    pam_kanidm.so
    session optional    pam_env.so

> **WARNING:** Ensure that `pam_mkhomedir` or `pam_oddjobd` are *not* present in any stage of your
> pam configuration, as they interfere with the correct operation of the kanidm tasks daemon.

### Fedora / CentOS

> **WARNING:** Kanidm currently has no support for SELinux policy - this may mean you need to
> run the daemon with permissive mode for the unconfined_service_t daemon type. To do this run:
> `semanage permissive -a unconfined_service_t`. To undo this run `semanage permissive -d unconfined_service_t`.
>
> You may also need to run `audit2allow` for sshd and other types to be able to access the unix daemon sockets.

These files are managed by authselect as symlinks. You can either work with authselect, or remove the symlinks first.

#### Without authselect
If you just remove the symlinks:
edit the content.

    # /etc/pam.d/password-auth
    auth        required                                     pam_env.so
    auth        required                                     pam_faildelay.so delay=2000000
    auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
    auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
    auth        sufficient                                   pam_unix.so nullok try_first_pass
    auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
    auth        sufficient                                   pam_kanidm.so ignore_unknown_user
    auth        required                                     pam_deny.so
    
    account     sufficient                                   pam_unix.so
    account     sufficient                                   pam_localuser.so
    account     sufficient                                   pam_usertype.so issystem
    account     sufficient                                   pam_kanidm.so ignore_unknown_user
    account     required                                     pam_permit.so
    
    password    requisite                                    pam_pwquality.so try_first_pass local_users_only
    password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok
    password    sufficient                                   pam_kanidm.so
    password    required                                     pam_deny.so
    
    session     optional                                     pam_keyinit.so revoke
    session     required                                     pam_limits.so
    -session    optional                                     pam_systemd.so
    session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
    session     required                                     pam_unix.so
    session     optional                                     pam_kanidm.so

-

    # /etc/pam.d/system-auth
    auth        required                                     pam_env.so
    auth        required                                     pam_faildelay.so delay=2000000
    auth        sufficient                                   pam_fprintd.so
    auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
    auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
    auth        sufficient                                   pam_unix.so nullok try_first_pass
    auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
    auth        sufficient                                   pam_kanidm.so ignore_unknown_user
    auth        required                                     pam_deny.so

    account     sufficient                                   pam_unix.so
    account     sufficient                                   pam_localuser.so
    account     sufficient                                   pam_usertype.so issystem
    account     sufficient                                   pam_kanidm.so ignore_unknown_user
    account     required                                     pam_permit.so

    password    requisite                                    pam_pwquality.so try_first_pass local_users_only
    password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok
    password    sufficient                                   pam_kanidm.so
    password    required                                     pam_deny.so

    session     optional                                     pam_keyinit.so revoke
    session     required                                     pam_limits.so
    -session    optional                                     pam_systemd.so
    session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
    session     required                                     pam_unix.so
    session     optional                                     pam_kanidm.so

#### With authselect
To work with authselect:
You will need to [create a new profile](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect_configuring-authentication-and-authorization-in-rhel#creating-and-deploying-your-own-authselect-profile_configuring-user-authentication-using-authselect). First run

    authselect create-profile kanidm -b sssd

A new folder, /etc/authselect/custom/kanidm, should be created. Inside that folder, create or overwrite the following 3 files: nsswitch.conf, password-auth, system-auth. password-auth and system-auth should be the same as above. nsswitch should be modified for your usecase, but a working example looks like this:

    passwd: compat kanidm sss files systemd
    group: compat kanidm sss files systemd
    shadow:     files
    hosts:      files dns myhostname
    services:   sss files
    netgroup:   sss files
    automount:  sss files
    
    aliases:    files
    ethers:     files
    gshadow:    files
    networks:   files dns
    protocols:  files
    publickey:  files
    rpc:        files

finally run

    authselect select custom/kanidm

to update your profile.

## Troubleshooting

### Check POSIX-status of group and config

If authentication is failing via PAM, make sure that a list of groups is configured in `/etc/kanidm/unixd`:

```
pam_allowed_login_groups = ["example_group"]
```

Check the status of the group with `kanidm group posix show example_group`. If you get something similar to the below:

```shell
> kanidm group posix show example_group
Using cached token for name idm_admin
Error -> Http(500, Some(InvalidAccountState("Missing class: account && posixaccount OR group && posixgroup")), "b71f137e-39f3-4368-9e58-21d26671ae24")
```

POSIX-enable the group with `kanidm group posix set example_group`. You should get a result similar to this when you search for your group name:

```shell
> kanidm group posix show example_group
[ spn: example_group@kanidm.example.com, gidnumber: 3443347205 name: example_group, uuid: b71f137e-39f3-4368-9e58-21d26671ae24 ]
```

Also, ensure the target user is in the group by running:

```
>  kanidm group list_members example_group
```

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

Check that the `/var/run/kanidm-unixd/sock` is 777, and that non-root readers can see it with
ls or other tools.

Ensure that `/var/run/kanidm-unixd/task_sock` is 700, and that it is owned by the kanidm unixd
process user.

### Check you can access the kanidm server

You can check this with the client tools:

    kanidm self whoami --name anonymous

### Ensure the libraries are correct.

You should have:

    /usr/lib64/libnss_kanidm.so.2
    /usr/lib64/security/pam_kanidm.so

The exact path *may* change depending on your distribution, `pam_unixd.so` should be co-located with pam_kanidm.so so looking for it findable with:

```
find /usr/ -name 'pam_unix.so'
```

For example, on a Debian machine, it's located in `/usr/lib/x86_64-linux-gnu/security/`.

### Increase connection timeout

In some high latency environments, you may need to increase the connection timeout. We set
this low to improve response on LANs, but over the internet this may need to be increased.
By increasing the conn timeout, you will be able to operate on higher latency links, but
some operations may take longer to complete causing a degree of latency. 

By increasing the cache_timeout, you will need to refresh "less" but it may mean on an 
account lockout or group change, that you need to wait until cache_timeout to see the effect 
(this has security implications)

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

There is an important distinction between these two - invalidated cache items may still
be yielded to a client request if the communication to the main Kanidm server is not
possible. For example, you may have your laptop in a park without wifi.

Clearing the cache, however, completely wipes all local data about all accounts and groups.
If you are relying on this cached (but invalid data) you may lose access to your accounts until
other communication issues have been resolved.

