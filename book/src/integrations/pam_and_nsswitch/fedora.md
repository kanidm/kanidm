# Fedora / CentOS

> [!WARNING]
>
> Kanidm currently has no support for SELinux policy - this may mean you need to run the daemon with permissive mode for
> the `unconfined_service_t` daemon type. To do this run: `semanage permissive -a unconfined_service_t`. To undo this
> run `semanage permissive -d unconfined_service_t`.
>
> You may also need to run `audit2allow` for sshd and other types to be able to access the UNIX daemon sockets.

These files are managed by authselect as symlinks. You can either work with authselect, or remove the symlinks first.

## Without authselect

If you just remove the symlinks:

Edit the content.

```text
# /etc/pam.d/system-auth
auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        sufficient                                   pam_fprintd.so
auth        sufficient                                   pam_kanidm.so ignore_unknown_user
auth        sufficient                                   pam_unix.so nullok
auth        required                                     pam_deny.so

account     sufficient                                   pam_kanidm.so ignore_unknown_user
account     required                                     pam_unix.so

password    requisite                                    pam_pwquality.so
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     optional                                     pam_kanidm.so
session     required                                     pam_unix.so

# /etc/pam.d/password-auth
auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        sufficient                                   pam_kanidm.so ignore_unknown_user
auth        sufficient                                   pam_unix.so nullok
auth        required                                     pam_deny.so

account     sufficient                                   pam_kanidm.so
account     required                                     pam_unix.so

password    requisite                                    pam_pwquality.so
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     optional                                     pam_kanidm.so
session     required                                     pam_unix.so
```

## With authselect

To work with authselect:

You will need to
[create a new profile](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect_configuring-authentication-and-authorization-in-rhel#creating-and-deploying-your-own-authselect-profile_configuring-user-authentication-using-authselect).

<!--TODO this URL is too short -->

First run the following command:

```bash
authselect create-profile kanidm -b sssd
```

A new folder, /etc/authselect/custom/kanidm, should be created. Inside that folder, create or overwrite the following
three files: nsswitch.conf, password-auth, system-auth. password-auth and system-auth should be the same as above.
nsswitch should be modified for your use case. A working example looks like this:

```text
passwd: kanidm compat systemd
group:  kanidm compat systemd
shadow:     files
hosts:      files dns myhostname
services:   files
netgroup:   files
automount:  files

aliases:    files
ethers:     files
gshadow:    files
networks:   files dns
protocols:  files
publickey:  files
rpc:        files
```

Then run:

```bash
authselect select custom/kanidm
```

to update your profile.
