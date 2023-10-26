# PAM and nsswitch

[PAM](http://linux-pam.org) and [nsswitch](https://en.wikipedia.org/wiki/Name_Service_Switch) are
the core mechanisms used by Linux and BSD clients to resolve identities from an IDM service like
Kanidm into accounts that can be used on the machine for various interactive tasks.

## The UNIX Daemon

Kanidm provides a UNIX daemon that runs on any client that wants to use PAM and nsswitch
integration. The daemon can cache the accounts for users who have unreliable networks, or who leave
the site where Kanidm is hosted. The daemon is also able to cache missing-entry responses to reduce
network traffic and Kanidm server load.

Additionally, running the daemon means that the PAM and nsswitch integration libraries can be small,
helping to reduce the attack surface of the machine. Similarly, a tasks daemon is available that can
create home directories on first login and supports several features related to aliases and links to
these home directories.

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

> **NOTE** The `kanidm_unixd_tasks` daemon is not required for PAM and nsswitch functionality. If
> disabled, your system will function as usual. It is, however, recommended due to the features it
> provides supporting Kanidm's capabilities.

Both unixd daemons use the connection configuration from /etc/kanidm/config. This is the covered in
[client_tools](../client_tools.md#kanidm-configuration).

You can also configure some unixd-specific options with the file /etc/kanidm/unixd:

```toml
pam_allowed_login_groups = ["posix_group"]
default_shell = "/bin/sh"
home_prefix = "/home/"
home_attr = "uuid"
home_alias = "spn"
use_etc_skel = false
uid_attr_map = "spn"
gid_attr_map = "spn"
selinux = true
allow_local_account_override = ["account_name"]
```

`pam_allowed_login_groups` defines a set of POSIX groups where membership of any of these groups
will be allowed to login via PAM. All POSIX users and groups can be resolved by nss regardless of
PAM login status. This may be a group name, spn, or uuid.

`default_shell` is the default shell for users. Defaults to `/bin/sh`.

`home_prefix` is the prepended path to where home directories are stored. Must end with a trailing
`/`. Defaults to `/home/`.

`home_attr` is the default token attribute used for the home directory path. Valid choices are
`uuid`, `name`, `spn`. Defaults to `uuid`.

`home_alias` is the default token attribute used for generating symlinks pointing to the user's home
directory. If set, this will become the value of the home path to nss calls. It is recommended you
choose a "human friendly" attribute here. Valid choices are `none`, `uuid`, `name`, `spn`. Defaults
to `spn`.

> **NOTICE:** All users in Kanidm can change their name (and their spn) at any time. If you change
> `home_attr` from `uuid` you _must_ have a plan on how to manage these directory renames in your
> system. We recommend that you have a stable ID (like the UUID), and symlinks from the name to the
> UUID folder. Automatic support is provided for this via the unixd tasks daemon, as documented
> here.
>
> **NOTE:** Ubuntu users please see:
> [Why aren't snaps launching with home_alias set?](../frequently_asked_questions.md#why-arent-snaps-launching-with-home_alias-set)

`use_etc_skel` controls if home directories should be prepopulated with the contents of `/etc/skel`
when first created. Defaults to false.

`uid_attr_map` chooses which attribute is used for domain local users in presentation. Defaults to
`spn`. Users from a trust will always use spn.

`gid_attr_map` chooses which attribute is used for domain local groups in presentation. Defaults to
`spn`. Groups from a trust will always use spn.

`selinux` controls whether the `kanidm_unixd_tasks` daemon should detect and enable SELinux runtime
compatibility features to ensure that newly created home directories are labeled correctly. This
setting as no bearing on systems without SELinux, as these features will automatically be disabled
if SELinux is not detected when the daemon starts. Note that `kanidm_unixd_tasks` must also be built
with the SELinux feature flag for this functionality. Defaults to true.

`allow_local_account_override` allows kanidm to "override" the content of a user or group that is
defined locally. By default kanidm will detect when a user/group conflict with their entries from
`/etc/passwd` or `/etc/group` and will ignore the kanidm entry. However if you want kanidm to
override users or groups from the local system, you must list them in this field. Note that this can
have many unexpected consequences, so it is not recommended to enable this.

You can then check the communication status of the daemon:

```bash
kanidm-unix status
```

If the daemon is working, you should see:

```text
working!
```

If it is not working, you will see an error message:

```text
[2020-02-14T05:58:10Z ERROR kanidm-unix] Error ->
   Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }
```

For more information, see the [Troubleshooting](./pam_and_nsswitch.md#troubleshooting) section.

## nsswitch

When the daemon is running you can add the nsswitch libraries to /etc/nsswitch.conf

```text
passwd: compat kanidm
group: compat kanidm
```

You can [create a user](../accounts_and_groups.md#creating-accounts) then
[enable POSIX feature on the user](../posix_accounts.md#enabling-posix-attributes-on-accounts).

You can then test that the POSIX extended user is able to be resolved with:

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

> **HINT** Remember to also create a UNIX password with something like
> `kanidm account posix set_password --name idm_admin demo_user`. Otherwise there will be no
> credential for the account to authenticate with.

## PAM

> **WARNING:** Modifications to PAM configuration _may_ leave your system in a state where you are
> unable to login or authenticate. You should always have a recovery shell open while making changes
> (for example, root), or have access to single-user mode at the machine's console.

Pluggable Authentication Modules (PAM) is the mechanism a UNIX-like system that authenticates users,
and to control access to some resources. This is configured through a stack of modules that are
executed in order to evaluate the request, and then each module may request or reuse authentication
token information.

### Before You Start

You _should_ backup your /etc/pam.d directory from its original state as you _may_ change the PAM
configuration in a way that will not allow you to authenticate to your machine.

```bash
cp -a /etc/pam.d /root/pam.d.backup
```

### Configuration Examples

Documentation examples for the following Linux distributions are available:

* [Fedora](pam_and_nsswitch/fedora.md)
* [SUSE / OpenSUSE](pam_and_nsswitch/suse.md)
* Debian / Ubuntu - when one generates packages [from the repository tools](https://github.com/kanidm/kanidm/tree/master/platform/debian), configuration is modified on install.
