# Troubleshooting PAM/nsswitch

## Check POSIX-status of Group and Configuration

If authentication is failing via PAM, make sure that you enabled the Kanidm provider and that
a list of valid groups is configured in `/etc/kanidm/unixd`. The `[kanidm]` line is important!

You can check the provider status, the second line is only shown if enabled:

```bash
> kanidm-unix status
system: online
Kanidm: online
```

Example of a minimum `/etc/kanidm/unixd` config:

```toml
[kanidm]
pam_allowed_login_groups = ["example_group"]
```

Check the status of the group with `kanidm group posix show example_group`. If you get something similar to the
following example:

```bash
> kanidm group posix show example_group
Using cached token for name idm_admin
Error -> Http(500, Some(InvalidAccountState("Missing class: account && posixaccount OR group && posixgroup")),
    "b71f137e-39f3-4368-9e58-21d26671ae24")
```

POSIX-enable the group with `kanidm group posix set example_group`. You should get a result similar to this when you
search for your group name:

```bash
> kanidm group posix show example_group
[ spn: example_group@kanidm.example.com, gidnumber: 3443347205 name: example_group, uuid: b71f137e-39f3-4368-9e58-21d26671ae24 ]
```

Also, ensure the target user is in the group by running:

```bash
>  kanidm group list_members example_group
```

## Increase Logging

For the unixd daemon, you can increase the logging with:

```bash
systemctl edit kanidm-unixd.service
```

And add the lines:

```ini
[Service]
Environment="RUST_LOG=kanidm=debug"
```

Then restart the kanidm-unixd.service.

The same pattern is true for the kanidm-unixd-tasks.service daemon.

To debug the pam module interactions add `debug` to the module arguments such as:

```text
auth sufficient pam_kanidm.so debug
```

## Check the Socket Permissions

Check that the `/var/run/kanidm-unixd/sock` has permissions mode 777, and that non-root readers can see it with ls or
other tools.

Ensure that `/var/run/kanidm-unixd/task_sock` has permissions mode 700, and that it is owned by the kanidm unixd process
user.

## Verify that You Can Access the Kanidm Server

You can check this with the client tools:

```bash
kanidm self whoami --name anonymous
```

## Ensure the Libraries are Correct

You should have:

```bash
/usr/lib64/libnss_kanidm.so.2
/usr/lib64/security/pam_kanidm.so
```

The exact path _may_ change depending on your distribution, `pam_unixd.so` should be co-located with pam_kanidm.so. Look
for it with the find command:

```bash
find /usr/ -name 'pam_unix.so'
```

For example, on a Debian machine, it's located in `/usr/lib/x86_64-linux-gnu/security/`.

## Increase Connection Timeout

In some high-latency environments, you may need to increase the connection timeout. We set this low to improve response
on LANs, but over the internet this may need to be increased. By increasing the conn_timeout, you will be able to
operate on higher latency links, but some operations may take longer to complete causing a degree of latency.

By increasing the cache_timeout, you will need to refresh less often, but it may result in an account lockout or group
change until cache_timeout takes effect. Note that this has security implications:

```toml
# /etc/kanidm/unixd
# Seconds
conn_timeout = 8
# Cache timeout
cache_timeout = 60
```

## Invalidate or Clear the Cache

You can invalidate the kanidm_unixd cache with:

```bash
kanidm-unix cache-invalidate
```

You can clear (wipe) the cache with:

```bash
kanidm-unix cache-clear
```

There is an important distinction between these two - invalidated cache items may still be yielded to a client request
if the communication to the main Kanidm server is not possible. For example, you may have your laptop in a park without
wifi.

Clearing the cache, however, completely wipes all local data about all accounts and groups. If you are relying on this
cached (but invalid) data, you may lose access to your accounts until other communication issues have been resolved.

## Home directories are not created via SSH

Ensure that `UsePAM yes` is set in `sshd_config`. Without this the pam session module won't be triggered which prevents
the background task being completed.
