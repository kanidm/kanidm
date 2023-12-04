# SUSE / OpenSUSE

To configure PAM on SUSE you must modify four files, which control the various stages of
authentication:

```bash
/etc/pam.d/common-account
/etc/pam.d/common-auth
/etc/pam.d/common-password
/etc/pam.d/common-session
```

> **IMPORTANT** By default these files are symlinks to their corresponding `-pc` file, for example
> `common-account -> common-account-pc`. If you directly edit these you are updating the inner
> content of the `-pc` file and it WILL be reset on a future upgrade. To prevent this you must first
> copy the `-pc` files. You can then edit the files safely.

```bash
# These steps must be taken as root
rm /etc/pam.d/common-account
rm /etc/pam.d/common-auth
rm /etc/pam.d/common-session
rm /etc/pam.d/common-password
cp /etc/pam.d/common-account-pc  /etc/pam.d/common-account
cp /etc/pam.d/common-auth-pc     /etc/pam.d/common-auth
cp /etc/pam.d/common-session-pc  /etc/pam.d/common-session
cp /etc/pam.d/common-password-pc /etc/pam.d/common-password
```

The content should look like:

```text
# /etc/pam.d/common-account
# Controls authorisation to this system (who may login)
account    [default=1 ignore=ignore success=ok] pam_localuser.so
account    sufficient    pam_unix.so
account    [default=1 ignore=ignore success=ok]  pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
account    sufficient    pam_kanidm.so ignore_unknown_user
account    required      pam_deny.so

# /etc/pam.d/common-auth
# Controls authentication to this system (verification of credentials)
auth        required      pam_env.so
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient    pam_kanidm.so ignore_unknown_user
auth        required      pam_deny.so

# /etc/pam.d/common-password
# Controls flow of what happens when a user invokes the passwd command. Currently does NOT
# push password changes back to kanidm
password    [default=1 ignore=ignore success=ok] pam_localuser.so
password    required    pam_unix.so use_authtok nullok shadow try_first_pass
password    [default=1 ignore=ignore success=ok]  pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
password    required    pam_kanidm.so

# /etc/pam.d/common-session
# Controls setup of the user session once a successful authentication and authorisation has
# occurred.
session optional    pam_systemd.so
session required    pam_limits.so
session optional    pam_unix.so try_first_pass
session optional    pam_umask.so
session [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 1000 quiet_success quiet_fail
session optional    pam_kanidm.so
session optional    pam_env.so
```

> **WARNING:** Ensure that `pam_mkhomedir` or `pam_oddjobd` are _not_ present in any stage of your
> PAM configuration, as they interfere with the correct operation of the Kanidm tasks daemon.
