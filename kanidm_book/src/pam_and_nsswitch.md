# Pam and nsswitch

Pam and nsswitch are the core mechanisms used by Linux and Bsd clients
to resolve identities from an IDM service like kanidm into accounts that
can be used on the machine for various interactive tasks.

## The unix daemon

Kanidm provide a unix daemon that runs on any client that wants to use pam
and nsswitch integration. This is provided as the daemon can cache the accounts
for users who have unreliable networks or leave the site where kanidm is.
Additionally, the daemon means that the pam and nsswitch integration libraries
can be small, helping to reduce the attack surface of the machine.

We recommend you install the client daemon from your system package manager.

You can check the daemon is running on your Linux system with

    # systemctl status kanidm_unixd

This daemon uses configuration from /etc/kanidm/config. This is the covered in
client_tools.

You can then check the communication status of the daemon as any user account.

    $ kanidm_unixd_status

If the daemon is working, you should see:

    [2020-02-14T05:58:37Z INFO  kanidm_unixd_status] working!

If it is not working, you will see an error message:

    [2020-02-14T05:58:10Z ERROR kanidm_unixd_status] Error -> Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }

For more, see troubleshooting.

## nsswitch

When the daemon is running you can add the nsswitch libraries to /etc/nsswitch.conf

    passwd: kanidm compat
    group: kanidm compat

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

TBD

## Troubleshooting

### Check the socket permissions

Check that the /var/run/kanidm.sock is 777, and that non-root readers can see it with
ls or other tools.

### Check you can access the kanidm server

You can check this with the client tools:

    kanidm self whoami --name anonymous

### Ensure the libraries are correct.

You should have:

    /usr/lib64/libnss_kanidm.so.2

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

