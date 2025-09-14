# PAM and nsswitch

[PAM](http://linux-pam.org) and [nsswitch](https://en.wikipedia.org/wiki/Name_Service_Switch) are the core mechanisms
used by Linux and BSD clients to resolve identities from an IDM service like Kanidm into accounts that can be used on
the machine for various interactive tasks.

## The UNIX Daemon

Kanidm provides a UNIX daemon that runs on any client that wants to support PAM and nsswitch. This service has many
features which are useful even without Kanidm as a network authentication service.

The Kanidm UNIX Daemon:

- Caches Kanidm users and groups for users with unreliable networks, or for roaming users.
- Securely caches user credentials with optional TPM backed cryptographic operations.
- Automatically creates home directories for users.
- Caches and resolves the content of `/etc/passwd` and `/etc/group` improving system performance.
- Has a small set of hardened libraries to reduce attack surface.

We recommend you install the client daemon from your system package manager:

```bash
# OpenSUSE
zypper in kanidm-unixd-clients
# Fedora
dnf install kanidm-unixd-clients
```

You can check the daemon is running on your Linux system with:

```bash
systemctl status kanidm-unixd
```

You can check the privileged tasks daemon is running with:

```bash
systemctl status kanidm-unixd-tasks
```

> [!NOTE]
>
> `kanidm-unixd-tasks` is now required, which is a change where it was previously optional.

You can also configure unixd with the file /etc/kanidm/unixd:

> [!NOTE]
>
> All users in Kanidm can change their name (and their spn) at any time. If you change `home_attr` from `uuid` you
> _must_ have a plan on how to manage these directory renames in your system. We recommend that you have a stable ID
> (like the UUID), and symlinks from the name to the UUID folder. Automatic support is provided for this via the unixd
> tasks daemon, as documented here.
>
> Ubuntu users please see:
> [Why aren't snaps launching with home_alias set?](../frequently_asked_questions.md#why-arent-snaps-launching-with-home_alias-set)

```toml
{{#rustdoc_include ../../../examples/unixd}}
```

If you are using the Kanidm provider features, you also need to configure `/etc/kanidm/config`. This is the covered in
[client_tools](../client_tools.md#kanidm-configuration). At a minimum the `uri` option must be set.

You can start, and then check the status of the daemon with the following commands:

```bash
systemctl enable --now kanidm-unixd
kanidm-unix status
```

If the daemon is working, you should see:

```text
system: online
Kanidm: online
```

If it is not working, you will see an error message:

```text
[2020-02-14T05:58:10Z ERROR kanidm-unix] Error ->
   Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }
```

If the unixd daemon is running but not configured to use the Kanidm provider, only system status is reported:

```text
system: online
```

For more information, see the [Troubleshooting](pam_and_nsswitch/troubleshooting.md) section.

## Using a service account

## nsswitch

When the daemon is running you can add the nsswitch libraries to /etc/nsswitch.conf

```text
passwd: kanidm compat
group:  kanidm compat
```

> NOTE: Unlike other nsswitch modules, Kanidm should be before compat or files. This is because Kanidm caches and
> provides the content from `/etc/passwd` and `/etc/group`.

Then [create a user](../accounts/intro.md) and
[enable POSIX feature on the user](../accounts/posix_accounts_and_groups.md#enabling-posix-attributes-on-accounts).

Test that the POSIX extended user is able to be resolved with:

```bash
getent passwd <account name>
getent passwd testunix
testunix:x:3524161420:3524161420:testunix:/home/testunix:/bin/sh
```

You can also do the same for groups.

```bash
getent group <group name>
getent group testgroup
testgroup:x:2439676479:testunix
```

> [!HINT]
>
> Remember to also create a UNIX password with something like
> `kanidm person posix set-password --name idm_admin demo_user`. Otherwise there will be no credential for the account
> to authenticate with.

## PAM

> [!WARNING]
>
> Modifications to PAM configuration _may_ leave your system in a state where you are unable to login or authenticate.
> You should always have a recovery shell open while making changes (for example, root), or have access to single-user
> mode at the machine's console.

Pluggable Authentication Modules (PAM) is the mechanism a UNIX-like system that authenticates users, and to control
access to some resources. This is configured through a stack of modules that are executed in order to evaluate the
request, and then each module may request or reuse authentication token information.

### Before You Start

You _should_ backup your /etc/pam.d directory from its original state as you _may_ change the PAM configuration in a way
that will not allow you to authenticate to your machine.

```bash
cp -a /etc/pam.d /root/pam.d.backup
```

### Configuration Examples

Documentation examples for the following Linux distributions are available:

- [SUSE / OpenSUSE](pam_and_nsswitch/suse.md)
- [Fedora](pam_and_nsswitch/fedora.md)
- Debian / Ubuntu - Installed with the packages from [kanidm/kanidm_ppa](https://kanidm.github.io/kanidm_ppa/).
